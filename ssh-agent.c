/* $OpenBSD: ssh-agent.c,v 1.306 2024/03/09 05:12:13 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * The authentication agent program.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif
#include "openbsd-compat/sys-queue.h"

#ifdef WITH_OPENSSL
#include <openssl/evp.h>
#include <openssl/err.h>
#include "openbsd-compat/openssl-compat.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_UTIL_H
# include <util.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"
#include "log.h"
#include "misc.h"
#include "digest.h"
#include "ssherr.h"
#include "match.h"
#include "msg.h"
#include "pathnames.h"
#include "ssh-pkcs11.h"
#include "sk-api.h"
#include "myproposal.h"
#include "cipher.h"

#ifndef DEFAULT_ALLOWED_PROVIDERS
# define DEFAULT_ALLOWED_PROVIDERS "/usr/lib*/*,/usr/local/lib*/*"
#endif

/* Maximum accepted message length */
#define AGENT_MAX_LEN		(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN		(4096)
/* Maximum number of recorded session IDs/hostkeys per connection */
#define AGENT_MAX_SESSION_IDS		16
/* Maximum size of session ID */
#define AGENT_MAX_SID_LEN		128
/* Maximum number of destination constraints to accept on a key */
#define AGENT_MAX_DEST_CONSTRAINTS	1024
/* Maximum number of associated certificate constraints to accept on a key */
#define AGENT_MAX_EXT_CERTS		1024

/* XXX store hostkey_sid in a refcounted tree */

typedef enum {
	AUTH_UNUSED = 0,
	AUTH_SOCKET = 1,
	AUTH_CONNECTION = 2,
} sock_type;

struct hostkey_sid {
	struct sshkey *key;
	struct sshbuf *sid;
	int forwarded;
};

typedef struct socket_entry {
	int fd;
	sock_type type;
	struct sshbuf *input;
	struct sshbuf *output;
	struct sshbuf *request;
	size_t nsession_ids;
	struct hostkey_sid *session_ids;
	int session_bind_attempted;
} SocketEntry;

u_int sockets_alloc = 0;
SocketEntry *sockets = NULL;

typedef struct identity {
	TAILQ_ENTRY(identity) next;
	struct sshkey *key;
	char *comment;
	char *provider;
	time_t death;
	u_int confirm;
	char *sk_provider;
	struct dest_constraint *dest_constraints;
	size_t ndest_constraints;
} Identity;

struct idtable {
	int nentries;
	TAILQ_HEAD(idqueue, identity) idlist;
};

/* private key table */
struct idtable *idtab;

struct apdubuf {
	uint8_t *b_data;
	size_t b_offset;
	size_t b_size;
	size_t b_len;
};

enum piv_box_version {
	PIV_BOX_V1 = 0x01,
	/* Version 2 added the nonce field. */
	PIV_BOX_V2 = 0x02,
	PIV_BOX_VNEXT
};

enum piv_slotid {
	PIV_SLOT_9A = 0x9A,
	PIV_SLOT_9B = 0x9B,
	PIV_SLOT_9C = 0x9C,
	PIV_SLOT_9D = 0x9D,
	PIV_SLOT_9E = 0x9E,

	PIV_SLOT_82 = 0x82,
	PIV_SLOT_95 = 0x95,

	PIV_SLOT_F9 = 0xF9,

	PIV_SLOT_PIV_AUTH = PIV_SLOT_9A,
	PIV_SLOT_ADMIN = PIV_SLOT_9B,
	PIV_SLOT_SIGNATURE = PIV_SLOT_9C,
	PIV_SLOT_KEY_MGMT = PIV_SLOT_9D,
	PIV_SLOT_CARD_AUTH = PIV_SLOT_9E,

	PIV_SLOT_RETIRED_1 = PIV_SLOT_82,
	PIV_SLOT_RETIRED_20 = PIV_SLOT_95,

	PIV_SLOT_YK_ATTESTATION = PIV_SLOT_F9,
};

struct piv_ecdh_box {
	/* Actually one of the piv_box_version values */
	uint8_t pdb_version;

	/* If true, the pdb_guid/pdb_slot fields are populated. */
	int pdb_guidslot_valid;
	uint8_t pdb_guid[16];
	enum piv_slotid pdb_slot;

	/* Cached cstring hex version of pdb_guid */
	char *pdb_guidhex;

	/* The ephemeral public key that does DH with pdb_pub */
	struct sshkey *pdb_ephem_pub;
	/* The public key we intend to be able to unlock the box */
	struct sshkey *pdb_pub;

	/*
	 * If true, pdb_cipher/kdf were malloc'd by us and should be freed
	 * in piv_box_free()
	 */
	int pdb_free_str;
	const char *pdb_cipher;		/* OpenSSH cipher.c alg name */
	const char *pdb_kdf;		/* OpenSSH digest.c alg name */

	struct apdubuf pdb_nonce;
	struct apdubuf pdb_iv;
	struct apdubuf pdb_enc;

	/*
	 * Never written out as part of the box structure: the in-memory
	 * cached plaintext after we unseal a box goes here.
	 */
	struct apdubuf pdb_plain;

	/*
	 * This is for ebox to use to supply an alternative ephemeral _private_
	 * key for sealing (nobody else should use this!)
	 */
	struct sshkey *pdb_ephem;
};

int max_fd = 0;

/* pid of shell == parent of agent */
pid_t parent_pid = -1;
time_t parent_alive_interval = 0;

sig_atomic_t signalled = 0;

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];

/* Pattern-list of allowed PKCS#11/Security key paths */
static char *allowed_providers;

/*
 * Allows PKCS11 providers or SK keys that use non-internal providers to
 * be added over a remote connection (identified by session-bind@openssh.com).
 */
static int remote_add_provider;

/* Check connecting client UID */
static int check_uid = 1;

/* locking */
#define LOCK_SIZE	32
#define LOCK_SALT_SIZE	16
#define LOCK_ROUNDS	1
int locked = 0;
u_char lock_pwhash[LOCK_SIZE];
u_char lock_salt[LOCK_SALT_SIZE];

extern char *__progname;

/* Default lifetime in seconds (0 == forever) */
static int lifetime = 0;

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

/* Refuse signing of non-SSH messages for web-origin FIDO keys */
static int restrict_websafe = 1;

static int
sshbuf_put_piv_box(struct sshbuf *buf, struct piv_ecdh_box *box)
{
	int rc;
	const char *tname;
	uint8_t ver;

	if (box->pdb_pub->type != KEY_ECDSA ||
	    box->pdb_ephem_pub->type != KEY_ECDSA) {
		error("Box public key and ephemeral public key must both be "
		    "ECDSA keys (instead they are %s and %s)",
		    sshkey_type(box->pdb_pub),
		    sshkey_type(box->pdb_ephem_pub));
		return (SSH_ERR_INVALID_ARGUMENT);
	}
	if (box->pdb_pub->ecdsa_nid != box->pdb_ephem_pub->ecdsa_nid) {
		error("Box public and ephemeral key must be on the same "
		    "EC curve");
		return (SSH_ERR_INVALID_ARGUMENT);
	}

	if ((rc = sshbuf_put_u8(buf, 0xB0)) ||
	    (rc = sshbuf_put_u8(buf, 0xC5)))
		return (rc);
	ver = box->pdb_version;
	if ((rc = sshbuf_put_u8(buf, ver)))
		return (rc);
	if (!box->pdb_guidslot_valid) {
		if ((rc = sshbuf_put_u8(buf, 0x00)) ||
		    (rc = sshbuf_put_u8(buf, 0x00)) ||
		    (rc = sshbuf_put_u8(buf, 0x00)))
			return (rc);
	} else {
		if ((rc = sshbuf_put_u8(buf, 0x01)))
			return (rc);
		rc = sshbuf_put_string8(buf, box->pdb_guid,
		    sizeof (box->pdb_guid));
		if (rc)
			return (rc);
		if ((rc = sshbuf_put_u8(buf, box->pdb_slot)))
			return (rc);
	}
	if ((rc = sshbuf_put_cstring8(buf, box->pdb_cipher)) ||
	    (rc = sshbuf_put_cstring8(buf, box->pdb_kdf)))
		return (rc);

	if (ver >= PIV_BOX_V2) {
		if ((rc = sshbuf_put_string8(buf, box->pdb_nonce.b_data,
		    box->pdb_nonce.b_len)))
			return (rc);
	}

	tname = sshkey_curve_nid_to_name(box->pdb_pub->ecdsa_nid);
	if ((rc = sshbuf_put_cstring8(buf, tname)))
		return (rc);
	if ((rc = sshbuf_put_ec_pkey8(buf, box->pdb_pub->pkey)) ||
	    (rc = sshbuf_put_ec_pkey8(buf, box->pdb_ephem_pub->pkey)))
		return (rc);

	if ((rc = sshbuf_put_string8(buf, box->pdb_iv.b_data,
	    box->pdb_iv.b_len)))
		return (rc);

	if ((rc = sshbuf_put_string(buf, box->pdb_enc.b_data,
	    box->pdb_enc.b_len)))
		return (rc);

	return (0);
}

static int
sshbuf_get_eckey8_sshkey(struct sshbuf *buf, int nid, struct sshkey **outkey)
{
	struct sshkey *k = NULL;
	EC_KEY *eck = NULL;
	EVP_PKEY *pkey = NULL;
	int rc;

	k = sshkey_new(KEY_ECDSA);
	if (k == NULL) {
		rc = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	k->ecdsa_nid = nid;
	eck = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	if (eck == NULL) {
		rc = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((rc = sshbuf_get_eckey8(buf, eck)))
		goto out;
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(eck),
	    EC_KEY_get0_public_key(eck))))
		goto out;
	pkey = EVP_PKEY_new();
	if (pkey == NULL) {
		rc = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	EVP_PKEY_assign_EC_KEY(pkey, eck);
	eck = NULL;

	EVP_PKEY_free(k->pkey);
	k->pkey = pkey;
	pkey = NULL;

	*outkey = k;
	k = NULL;
	rc = 0;

out:
	EVP_PKEY_free(pkey);
	EC_KEY_free(eck);
	sshkey_free(k);
	return (rc);
}

static void
piv_box_free(struct piv_ecdh_box *box)
{
	if (box == NULL)
		return;
	sshkey_free(box->pdb_ephem_pub);
	sshkey_free(box->pdb_pub);
	if (box->pdb_free_str) {
		free((void *)box->pdb_cipher);
		free((void *)box->pdb_kdf);
	}
	free(box->pdb_iv.b_data);
	free(box->pdb_enc.b_data);
	free(box->pdb_nonce.b_data);
	free(box->pdb_guidhex);
	if (box->pdb_plain.b_data != NULL) {
		freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	}
	free(box);
}

static struct piv_ecdh_box *
piv_box_new(void)
{
	struct piv_ecdh_box *box;
	box = calloc(1, sizeof (struct piv_ecdh_box));
	box->pdb_version = PIV_BOX_VNEXT - 1;
	return (box);
}

static int
sshbuf_get_piv_box(struct sshbuf *buf, struct piv_ecdh_box **outbox)
{
	struct piv_ecdh_box *box = NULL;
	uint8_t ver, magic[2];
	int rc = 0;
	uint8_t *tmpbuf = NULL;
	size_t len;
	uint8_t temp;
	char *tname = NULL;
	int nid;

	box = piv_box_new();
	if (box == NULL)
		fatal("%s: memory allocation failed", __func__);

	if ((rc = sshbuf_get_u8(buf, &magic[0])) ||
	    (rc = sshbuf_get_u8(buf, &magic[1]))) {
		goto out;
	}
	if (magic[0] != 0xB0 && magic[1] != 0xC5) {
		verbose("%s: invalid magic (0x%02x%02x)", __func__,
		    magic[0], magic[1]);
		rc = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((rc = sshbuf_get_u8(buf, &ver))) {
		goto out;
	}
	if (ver < PIV_BOX_V1 || ver >= PIV_BOX_VNEXT) {
		verbose("%s: invalid box version: %d", __func__, ver);
		rc = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	box->pdb_version = ver;

	if ((rc = sshbuf_get_u8(buf, &temp))) {
		goto out;
	}
	box->pdb_guidslot_valid = (temp != 0x00);

	if ((rc = sshbuf_get_string8(buf, &tmpbuf, &len))) {
		goto out;
	}
	if (box->pdb_guidslot_valid && len != sizeof (box->pdb_guid)) {
		rc = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	} else if (box->pdb_guidslot_valid) {
		bcopy(tmpbuf, box->pdb_guid, len);
	}
	free(tmpbuf);
	tmpbuf = NULL;
	if ((rc = sshbuf_get_u8(buf, &temp))) {
		goto out;
	}
	if (box->pdb_guidslot_valid)
		box->pdb_slot = temp;

	box->pdb_free_str = 1;
	if ((rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_cipher, NULL)) ||
	    (rc = sshbuf_get_cstring8(buf, (char **)&box->pdb_kdf, NULL))) {
		goto out;
	}

	if (ver >= PIV_BOX_V2) {
		if ((rc = sshbuf_get_string8(buf, &box->pdb_nonce.b_data,
		    &box->pdb_nonce.b_size))) {
			goto out;
		}
		box->pdb_nonce.b_len = box->pdb_nonce.b_size;
	}

	if ((rc = sshbuf_get_cstring8(buf, &tname, NULL))) {
		goto out;
	}

	if ((nid = sshkey_curve_name_to_nid(tname)) == -1) {
		rc = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}
	rc = sshbuf_get_eckey8_sshkey(buf, nid, &box->pdb_pub);
	if (rc)
		goto out;

	rc = sshbuf_get_eckey8_sshkey(buf, nid, &box->pdb_ephem_pub);
	if (rc)
		goto out;

	if ((rc = sshbuf_get_string8(buf, &box->pdb_iv.b_data,
	    &box->pdb_iv.b_size))) {
		goto out;
	}
	box->pdb_iv.b_len = box->pdb_iv.b_size;
	if ((rc = sshbuf_get_string(buf, &box->pdb_enc.b_data,
	    &box->pdb_enc.b_size))) {
		goto out;
	}
	box->pdb_enc.b_len = box->pdb_enc.b_size;

	*outbox = box;
	box = NULL;
	rc = 0;

out:
	piv_box_free(box);
	free(tname);
	free(tmpbuf);
	return (rc);
}

static int
piv_box_open_offline(struct sshkey *privkey, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int dgalg;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen;
	size_t fieldsz, plainlen, enclen;
	size_t reallen, padding, i;
	int was_shielded = sshkey_is_shielded(privkey);
	int rv;
	const EC_KEY *eck, *epheck;

	cipher = cipher_by_name(box->pdb_cipher);
	if (cipher == NULL) {
		char *temp = malloc(strlen(box->pdb_cipher) + 13);
		if (temp == NULL)
			return (SSH_ERR_ALLOC_FAIL);
		temp[0] = 0;
		strcat(temp, box->pdb_cipher);
		strcat(temp, "@openssh.com");
		cipher = cipher_by_name(temp);
		free(temp);
		if (cipher == NULL) {
			verbose("%s: unknown cipher: %s", __func__,
			    box->pdb_cipher);
			return (SSH_ERR_KEY_TYPE_UNKNOWN);
		}
	}
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	/* TODO: support non-authenticated ciphers by adding an HMAC */
	if (authlen == 0) {
		verbose("%s: non-authenticated cipher", __func__);
		return (SSH_ERR_KEY_TYPE_MISMATCH);
	}

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	if (dgalg == -1) {
		verbose("%s: unknown digest alg: %s", __func__, box->pdb_kdf);
		return (SSH_ERR_KEY_TYPE_UNKNOWN);
	}
	dglen = ssh_digest_bytes(dgalg);
	if (dglen < keylen) {
		verbose("%s: dglen/keylen mismatch", __func__);
		return (SSH_ERR_KEY_TYPE_MISMATCH);
	}

	eck = EVP_PKEY_get1_EC_KEY(privkey->pkey);
	epheck = EVP_PKEY_get1_EC_KEY(box->pdb_ephem_pub->pkey);

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(eck));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	if (sec == NULL)
		fatal("%s: memory allocation failed", __func__);

	if ((rv = sshkey_unshield_private(privkey)) != 0) {
		verbose("%s: failed to unshield: %s", __func__, ssh_err(rv));
		return (rv);

	}

	/* fetch this again in case unshield changed it */
	eck = EVP_PKEY_get1_EC_KEY(privkey->pkey);

	rv = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(epheck), eck,
	    NULL);

	if (was_shielded)
		sshkey_shield_private(privkey);
	if (rv <= 0) {
		unsigned long ssl_err = ERR_peek_last_error();
		free(sec);
		error("%s: openssl error: %ld: %s", __func__, ssl_err,
		    ERR_error_string(ssl_err, NULL));
		return (SSH_ERR_LIBCRYPTO_ERROR);
	}
	seclen = (size_t)rv;

	dgctx = ssh_digest_start(dgalg);
	if (dgctx == NULL)
		fatal("%s: memory allocation failed", __func__);
	ssh_digest_update(dgctx, sec, seclen);
	if (box->pdb_nonce.b_len > 0) {
		/*
		 * In the original libnacl/libsodium box primitive, the nonce
		 * is combined with the ECDH output in a more complex way than
		 * this. Based on reading the RFCs for systems like OpenSSH,
		 * though, this method (simply concat'ing them and hashing)
		 * seems to be acceptable.
		 *
		 * We never publish this hash value (it's the symmetric key!)
		 * so we don't need to worry about length extension attacks and
		 * similar.
		 */
		ssh_digest_update(dgctx, box->pdb_nonce.b_data +
		    box->pdb_nonce.b_offset, box->pdb_nonce.b_len);
	}
	key = calloc(1, dglen);
	if (key == NULL)
		fatal("%s: memory allocation failed", __func__);
	ssh_digest_final(dgctx, key, dglen);
	ssh_digest_free(dgctx);

	freezero(sec, seclen);

	iv = box->pdb_iv.b_data + box->pdb_iv.b_offset;
	if (box->pdb_iv.b_len != ivlen) {
		return (SSH_ERR_MESSAGE_INCOMPLETE);
	}

	enc = box->pdb_enc.b_data + box->pdb_enc.b_offset;
	enclen = box->pdb_enc.b_len;
	if (enclen < authlen + blocksz) {
		return (SSH_ERR_MESSAGE_INCOMPLETE);
	}

	plainlen = enclen - authlen;
	plain = calloc(1, plainlen);
	if (plain == NULL)
		fatal("%s: memory allocation failed", __func__);

	cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 0);
	rv = cipher_crypt(cctx, 0, plain, enc, enclen - authlen, 0,
	    authlen);
	cipher_free(cctx);

	freezero(key, dglen);

	if (rv != 0) {
		return (rv);
	}

	/* Strip off the pkcs#7 padding and verify it. */
	padding = plain[plainlen - 1];
	if (padding < 1 || padding > blocksz)
		goto paderr;
	reallen = plainlen - padding;
	for (i = reallen; i < plainlen; ++i) {
		if (plain[i] != padding) {
			goto paderr;
		}
	}

	if (box->pdb_plain.b_data != NULL) {
		freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	}
	box->pdb_plain.b_data = plain;
	box->pdb_plain.b_size = plainlen;
	box->pdb_plain.b_len = reallen;
	box->pdb_plain.b_offset = 0;

	return (0);

paderr:
	freezero(plain, plainlen);
	return (SSH_ERR_MAC_INVALID);
}

static int
piv_box_set_data(struct piv_ecdh_box *box, const uint8_t *data, size_t len)
{
	uint8_t *buf;
	if (box->pdb_plain.b_data != NULL)
		fatal("%s: box already full", __func__);

	buf = calloc(1, len);
	if (buf == NULL)
		return (SSH_ERR_ALLOC_FAIL);
	box->pdb_plain.b_data = buf;
	box->pdb_plain.b_size = len;
	box->pdb_plain.b_len = len;
	box->pdb_plain.b_offset = 0;

	bcopy(data, buf, len);

	return (0);
}

static int
piv_box_take_data(struct piv_ecdh_box *box, uint8_t **data, size_t *len)
{
	if (box->pdb_plain.b_data == NULL) {
		return (SSH_ERR_CONN_CLOSED);
	}

	*data = calloc(1, box->pdb_plain.b_len);
	if (*data == NULL)
		return (SSH_ERR_ALLOC_FAIL);
	*len = box->pdb_plain.b_len;
	bcopy(box->pdb_plain.b_data + box->pdb_plain.b_offset, *data, *len);

	freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;
	box->pdb_plain.b_offset = 0;

	return (0);
}

static int
piv_box_to_binary(struct piv_ecdh_box *box, uint8_t **output, size_t *len)
{
	struct sshbuf *buf;
	int r;

	buf = sshbuf_new();
	if (buf == NULL)
		return (SSH_ERR_ALLOC_FAIL);

	if ((r = sshbuf_put_piv_box(buf, box)) != 0) {
		sshbuf_free(buf);
		return (r);
	}

	*len = sshbuf_len(buf);
	*output = calloc(1, *len);
	if (*output == NULL) {
		sshbuf_free(buf);
		return (SSH_ERR_ALLOC_FAIL);
	}
	bcopy(sshbuf_ptr(buf), *output, *len);
	sshbuf_free(buf);

	return (0);
}

#define	BOX_DEFAULT_CIPHER	"chacha20-poly1305"
#define	BOX_DEFAULT_KDF		"sha512"

static int
piv_box_seal_offline(struct sshkey *pubk, struct piv_ecdh_box *box)
{
	const struct sshcipher *cipher;
	int rv;
	int dgalg;
	struct sshkey *pkey;
	struct sshcipher_ctx *cctx;
	struct ssh_digest_ctx *dgctx;
	uint8_t *iv, *key, *sec, *enc, *plain, *nonce;
	size_t ivlen, authlen, blocksz, keylen, dglen, seclen, noncelen;
	size_t fieldsz, plainlen, enclen;
	size_t padding, i;
	const EC_KEY *eck, *epheck;

	if (pubk->type != KEY_ECDSA) {
		return (SSH_ERR_KEY_TYPE_MISMATCH);
	}

	if (box->pdb_ephem == NULL) {
		rv = sshkey_generate(KEY_ECDSA, sshkey_size(pubk), &pkey);
		if (rv != 0) {
			return (rv);
		}
	} else {
		pkey = box->pdb_ephem;
	}
	if ((rv = sshkey_from_private(pkey, &box->pdb_ephem_pub)) != 0)
		return (rv);

	if (box->pdb_cipher == NULL)
		box->pdb_cipher = BOX_DEFAULT_CIPHER;
	if (box->pdb_kdf == NULL)
		box->pdb_kdf = BOX_DEFAULT_KDF;

	cipher = cipher_by_name(box->pdb_cipher);
	if (cipher == NULL) {
		char *temp = malloc(strlen(box->pdb_cipher) + 13);
		if (temp == NULL)
			return (SSH_ERR_ALLOC_FAIL);
		temp[0] = 0;
		strcat(temp, box->pdb_cipher);
		strcat(temp, "@openssh.com");
		cipher = cipher_by_name(temp);
		free(temp);
		if (cipher == NULL) {
			verbose("%s: unknown cipher: %s", __func__,
			    box->pdb_cipher);
			return (SSH_ERR_KEY_TYPE_UNKNOWN);
		}
	}
	ivlen = cipher_ivlen(cipher);
	authlen = cipher_authlen(cipher);
	blocksz = cipher_blocksize(cipher);
	keylen = cipher_keylen(cipher);
	/* TODO: support non-authenticated ciphers by adding an HMAC */
	if (authlen == 0) {
		return (SSH_ERR_KEY_UNKNOWN_CIPHER);
	}

	if (box->pdb_version >= PIV_BOX_V2 && (
	    box->pdb_nonce.b_data == NULL || box->pdb_nonce.b_len == 0)) {
		noncelen = 16;
		nonce = calloc(1, noncelen);
		if (nonce == NULL)
			fatal("%s: memory alloc failed", __func__);
		arc4random_buf(nonce, noncelen);

		free(box->pdb_nonce.b_data);
		box->pdb_nonce.b_data = nonce;
		box->pdb_nonce.b_offset = 0;
		box->pdb_nonce.b_size = noncelen;
		box->pdb_nonce.b_len = noncelen;
	}

	dgalg = ssh_digest_alg_by_name(box->pdb_kdf);
	if (dgalg == -1) {
		return (SSH_ERR_KEY_UNKNOWN_CIPHER);
	}
	dglen = ssh_digest_bytes(dgalg);
	if (dglen < keylen) {
		return (SSH_ERR_KEY_TYPE_MISMATCH);
	}

	eck = EVP_PKEY_get1_EC_KEY(pkey->pkey);
	epheck = EVP_PKEY_get1_EC_KEY(pubk->pkey);

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(eck));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	if (sec == NULL)
		fatal("%s: memory alloc failed", __func__);
	rv = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(epheck), eck, NULL);
	if (rv <= 0) {
		free(sec);
		return (SSH_ERR_LIBCRYPTO_ERROR);
	}
	seclen = (size_t)rv;

	if (box->pdb_ephem == NULL)
		sshkey_free(pkey);

	dgctx = ssh_digest_start(dgalg);
	if (dgctx == NULL)
		fatal("%s: memory alloc failed", __func__);
	ssh_digest_update(dgctx, sec, seclen);
	if (box->pdb_nonce.b_len > 0) {
		/* See comment in piv_box_open_offline */
		ssh_digest_update(dgctx, box->pdb_nonce.b_data +
		    box->pdb_nonce.b_offset, box->pdb_nonce.b_len);
	}
	key = calloc(1, dglen);
	if (key == NULL)
		fatal("%s: memory alloc failed", __func__);
	ssh_digest_final(dgctx, key, dglen);
	ssh_digest_free(dgctx);

	freezero(sec, seclen);

	iv = calloc(1, ivlen);
	if (iv == NULL)
		fatal("%s: memory alloc failed", __func__);
	arc4random_buf(iv, ivlen);

	free(box->pdb_iv.b_data);
	box->pdb_iv.b_size = ivlen;
	box->pdb_iv.b_len = ivlen;
	box->pdb_iv.b_data = iv;
	box->pdb_iv.b_offset = 0;

	plainlen = box->pdb_plain.b_len;

	/*
	 * We add PKCS#7 style padding, consisting of up to a block of bytes,
	 * all set to the number of padding bytes added. This is easy to strip
	 * off after decryption and avoids the need to include and validate the
	 * real length of the payload separately.
	 */
	padding = blocksz - (plainlen % blocksz);
	if (padding > blocksz)
		fatal("%s: padding > blocksz", __func__);
	if (padding <= 0)
		fatal("%s: padding <= 0", __func__);
	plainlen += padding;
	plain = calloc(1, plainlen);
	if (plain == NULL)
		fatal("%s: memory alloc failed", __func__);
	bcopy(box->pdb_plain.b_data + box->pdb_plain.b_offset, plain,
	    box->pdb_plain.b_len);
	for (i = box->pdb_plain.b_len; i < plainlen; ++i)
		plain[i] = padding;

	freezero(box->pdb_plain.b_data, box->pdb_plain.b_size);
	box->pdb_plain.b_data = NULL;
	box->pdb_plain.b_size = 0;
	box->pdb_plain.b_len = 0;

	cipher_init(&cctx, cipher, key, keylen, iv, ivlen, 1);
	enclen = plainlen + authlen;
	enc = calloc(1, enclen);
	if (enc == NULL)
		fatal("%s: memory alloc failed", __func__);
	cipher_crypt(cctx, 0, enc, plain, plainlen, 0, authlen);
	cipher_free(cctx);

	freezero(plain, plainlen);
	freezero(key, dglen);

	if ((rv = sshkey_from_private(pubk, &box->pdb_pub)) != 0)
		fatal("%s: failed to copy key: %s", __func__, ssh_err(rv));

	free(box->pdb_enc.b_data);
	box->pdb_enc.b_data = enc;
	box->pdb_enc.b_size = enclen;
	box->pdb_enc.b_len = enclen;
	box->pdb_enc.b_offset = 0;

	return (0);
}

static void
close_socket(SocketEntry *e)
{
	size_t i;

	close(e->fd);
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
	for (i = 0; i < e->nsession_ids; i++) {
		sshkey_free(e->session_ids[i].key);
		sshbuf_free(e->session_ids[i].sid);
	}
	free(e->session_ids);
	memset(e, '\0', sizeof(*e));
	e->fd = -1;
	e->type = AUTH_UNUSED;
}

static void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

static void
free_dest_constraint_hop(struct dest_constraint_hop *dch)
{
	u_int i;

	if (dch == NULL)
		return;
	free(dch->user);
	free(dch->hostname);
	for (i = 0; i < dch->nkeys; i++)
		sshkey_free(dch->keys[i]);
	free(dch->keys);
	free(dch->key_is_ca);
}

static void
free_dest_constraints(struct dest_constraint *dcs, size_t ndcs)
{
	size_t i;

	for (i = 0; i < ndcs; i++) {
		free_dest_constraint_hop(&dcs[i].from);
		free_dest_constraint_hop(&dcs[i].to);
	}
	free(dcs);
}

#ifdef ENABLE_PKCS11
static void
dup_dest_constraint_hop(const struct dest_constraint_hop *dch,
    struct dest_constraint_hop *out)
{
	u_int i;
	int r;

	out->user = dch->user == NULL ? NULL : xstrdup(dch->user);
	out->hostname = dch->hostname == NULL ? NULL : xstrdup(dch->hostname);
	out->is_ca = dch->is_ca;
	out->nkeys = dch->nkeys;
	out->keys = out->nkeys == 0 ? NULL :
	    xcalloc(out->nkeys, sizeof(*out->keys));
	out->key_is_ca = out->nkeys == 0 ? NULL :
	    xcalloc(out->nkeys, sizeof(*out->key_is_ca));
	for (i = 0; i < dch->nkeys; i++) {
		if (dch->keys[i] != NULL &&
		    (r = sshkey_from_private(dch->keys[i],
		    &(out->keys[i]))) != 0)
			fatal_fr(r, "copy key");
		out->key_is_ca[i] = dch->key_is_ca[i];
	}
}

static struct dest_constraint *
dup_dest_constraints(const struct dest_constraint *dcs, size_t ndcs)
{
	size_t i;
	struct dest_constraint *ret;

	if (ndcs == 0)
		return NULL;
	ret = xcalloc(ndcs, sizeof(*ret));
	for (i = 0; i < ndcs; i++) {
		dup_dest_constraint_hop(&dcs[i].from, &ret[i].from);
		dup_dest_constraint_hop(&dcs[i].to, &ret[i].to);
	}
	return ret;
}
#endif /* ENABLE_PKCS11 */

#ifdef DEBUG_CONSTRAINTS
static void
dump_dest_constraint_hop(const struct dest_constraint_hop *dch)
{
	u_int i;
	char *fp;

	debug_f("user %s hostname %s is_ca %d nkeys %u",
	    dch->user == NULL ? "(null)" : dch->user,
	    dch->hostname == NULL ? "(null)" : dch->hostname,
	    dch->is_ca, dch->nkeys);
	for (i = 0; i < dch->nkeys; i++) {
		fp = NULL;
		if (dch->keys[i] != NULL &&
		    (fp = sshkey_fingerprint(dch->keys[i],
		    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug_f("key %u/%u: %s%s%s key_is_ca %d", i, dch->nkeys,
		    dch->keys[i] == NULL ? "" : sshkey_ssh_name(dch->keys[i]),
		    dch->keys[i] == NULL ? "" : " ",
		    dch->keys[i] == NULL ? "none" : fp,
		    dch->key_is_ca[i]);
		free(fp);
	}
}
#endif /* DEBUG_CONSTRAINTS */

static void
dump_dest_constraints(const char *context,
    const struct dest_constraint *dcs, size_t ndcs)
{
#ifdef DEBUG_CONSTRAINTS
	size_t i;

	debug_f("%s: %zu constraints", context, ndcs);
	for (i = 0; i < ndcs; i++) {
		debug_f("constraint %zu / %zu: from: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].from);
		debug_f("constraint %zu / %zu: to: ", i, ndcs);
		dump_dest_constraint_hop(&dcs[i].to);
	}
	debug_f("done for %s", context);
#endif /* DEBUG_CONSTRAINTS */
}

static void
free_identity(Identity *id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id->sk_provider);
	free_dest_constraints(id->dest_constraints, id->ndest_constraints);
	free(id);
}

/*
 * Match 'key' against the key/CA list in a destination constraint hop
 * Returns 0 on success or -1 otherwise.
 */
static int
match_key_hop(const char *tag, const struct sshkey *key,
    const struct dest_constraint_hop *dch)
{
	const char *reason = NULL;
	const char *hostname = dch->hostname ? dch->hostname : "(ORIGIN)";
	u_int i;
	char *fp;

	if (key == NULL)
		return -1;
	/* XXX logspam */
	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");
	debug3_f("%s: entering hostname %s, requested key %s %s, %u keys avail",
	    tag, hostname, sshkey_type(key), fp, dch->nkeys);
	free(fp);
	for (i = 0; i < dch->nkeys; i++) {
		if (dch->keys[i] == NULL)
			return -1;
		/* XXX logspam */
		if ((fp = sshkey_fingerprint(dch->keys[i], SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug3_f("%s: key %u: %s%s %s", tag, i,
		    dch->key_is_ca[i] ? "CA " : "",
		    sshkey_type(dch->keys[i]), fp);
		free(fp);
		if (!sshkey_is_cert(key)) {
			/* plain key */
			if (dch->key_is_ca[i] ||
			    !sshkey_equal(key, dch->keys[i]))
				continue;
			return 0;
		}
		/* certificate */
		if (!dch->key_is_ca[i])
			continue;
		if (key->cert == NULL || key->cert->signature_key == NULL)
			return -1; /* shouldn't happen */
		if (!sshkey_equal(key->cert->signature_key, dch->keys[i]))
			continue;
		if (sshkey_cert_check_host(key, hostname, 1,
		    SSH_ALLOWED_CA_SIGALGS, &reason) != 0) {
			debug_f("cert %s / hostname %s rejected: %s",
			    key->cert->key_id, hostname, reason);
			continue;
		}
		return 0;
	}
	return -1;
}

/* Check destination constraints on an identity against the hostkey/user */
static int
permitted_by_dest_constraints(const struct sshkey *fromkey,
    const struct sshkey *tokey, Identity *id, const char *user,
    const char **hostnamep)
{
	size_t i;
	struct dest_constraint *d;

	if (hostnamep != NULL)
		*hostnamep = NULL;
	for (i = 0; i < id->ndest_constraints; i++) {
		d = id->dest_constraints + i;
		/* XXX remove logspam */
		debug2_f("constraint %zu %s%s%s (%u keys) > %s%s%s (%u keys)",
		    i, d->from.user ? d->from.user : "",
		    d->from.user ? "@" : "",
		    d->from.hostname ? d->from.hostname : "(ORIGIN)",
		    d->from.nkeys,
		    d->to.user ? d->to.user : "", d->to.user ? "@" : "",
		    d->to.hostname ? d->to.hostname : "(ANY)", d->to.nkeys);

		/* Match 'from' key */
		if (fromkey == NULL) {
			/* We are matching the first hop */
			if (d->from.hostname != NULL || d->from.nkeys != 0)
				continue;
		} else if (match_key_hop("from", fromkey, &d->from) != 0)
			continue;

		/* Match 'to' key */
		if (tokey != NULL && match_key_hop("to", tokey, &d->to) != 0)
			continue;

		/* Match user if specified */
		if (d->to.user != NULL && user != NULL &&
		    !match_pattern(user, d->to.user))
			continue;

		/* successfully matched this constraint */
		if (hostnamep != NULL)
			*hostnamep = d->to.hostname;
		debug2_f("allowed for hostname %s",
		    d->to.hostname == NULL ? "*" : d->to.hostname);
		return 0;
	}
	/* no match */
	debug2_f("%s identity \"%s\" not permitted for this destination",
	    sshkey_type(id->key), id->comment);
	return -1;
}

/*
 * Check whether hostkeys on a SocketEntry and the optionally specified user
 * are permitted by the destination constraints on the Identity.
 * Returns 0 on success or -1 otherwise.
 */
static int
identity_permitted(Identity *id, SocketEntry *e, char *user,
    const char **forward_hostnamep, const char **last_hostnamep)
{
	size_t i;
	const char **hp;
	struct hostkey_sid *hks;
	const struct sshkey *fromkey = NULL;
	const char *test_user;
	char *fp1, *fp2;

	/* XXX remove logspam */
	debug3_f("entering: key %s comment \"%s\", %zu socket bindings, "
	    "%zu constraints", sshkey_type(id->key), id->comment,
	    e->nsession_ids, id->ndest_constraints);
	if (id->ndest_constraints == 0)
		return 0; /* unconstrained */
	if (e->session_bind_attempted && e->nsession_ids == 0) {
		error_f("previous session bind failed on socket");
		return -1;
	}
	if (e->nsession_ids == 0)
		return 0; /* local use */
	/*
	 * Walk through the hops recorded by session_id and try to find a
	 * constraint that satisfies each.
	 */
	for (i = 0; i < e->nsession_ids; i++) {
		hks = e->session_ids + i;
		if (hks->key == NULL)
			fatal_f("internal error: no bound key");
		/* XXX remove logspam */
		fp1 = fp2 = NULL;
		if (fromkey != NULL &&
		    (fp1 = sshkey_fingerprint(fromkey, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		if ((fp2 = sshkey_fingerprint(hks->key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug3_f("socketentry fd=%d, entry %zu %s, "
		    "from hostkey %s %s to user %s hostkey %s %s",
		    e->fd, i, hks->forwarded ? "FORWARD" : "AUTH",
		    fromkey ? sshkey_type(fromkey) : "(ORIGIN)",
		    fromkey ? fp1 : "", user ? user : "(ANY)",
		    sshkey_type(hks->key), fp2);
		free(fp1);
		free(fp2);
		/*
		 * Record the hostnames for the initial forwarding and
		 * the final destination.
		 */
		hp = NULL;
		if (i == e->nsession_ids - 1)
			hp = last_hostnamep;
		else if (i == 0)
			hp = forward_hostnamep;
		/* Special handling for final recorded binding */
		test_user = NULL;
		if (i == e->nsession_ids - 1) {
			/* Can only check user at final hop */
			test_user = user;
			/*
			 * user is only presented for signature requests.
			 * If this is the case, make sure last binding is not
			 * for a forwarding.
			 */
			if (hks->forwarded && user != NULL) {
				error_f("tried to sign on forwarding hop");
				return -1;
			}
		} else if (!hks->forwarded) {
			error_f("tried to forward though signing bind");
			return -1;
		}
		if (permitted_by_dest_constraints(fromkey, hks->key, id,
		    test_user, hp) != 0)
			return -1;
		fromkey = hks->key;
	}
	/*
	 * Another special case: if the last bound session ID was for a
	 * forwarding, and this function is not being called to check a sign
	 * request (i.e. no 'user' supplied), then only permit the key if
	 * there is a permission that would allow it to be used at another
	 * destination. This hides keys that are allowed to be used to
	 * authenticate *to* a host but not permitted for *use* beyond it.
	 */
	hks = &e->session_ids[e->nsession_ids - 1];
	if (hks->forwarded && user == NULL &&
	    permitted_by_dest_constraints(hks->key, NULL, id,
	    NULL, NULL) != 0) {
		debug3_f("key permitted at host but not after");
		return -1;
	}

	/* success */
	return 0;
}

static int
socket_is_remote(SocketEntry *e)
{
	return e->session_bind_attempted || (e->nsession_ids != 0);
}

/* return matching private key for given public key */
static Identity *
lookup_identity(struct sshkey *key)
{
	Identity *id;

	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if (sshkey_equal(key, id->key))
			return (id);
	}
	return (NULL);
}

/* Check confirmation of keysign request */
static int
confirm_key(Identity *id, const char *extra)
{
	char *p;
	int ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	if (p != NULL &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.%s%s",
	    id->comment, p,
	    extra == NULL ? "" : "\n", extra == NULL ? "" : extra))
		ret = 0;
	free(p);

	return (ret);
}

static void
send_status(SocketEntry *e, int success)
{
	int r;

	if ((r = sshbuf_put_u32(e->output, 1)) != 0 ||
	    (r = sshbuf_put_u8(e->output, success ?
	    SSH_AGENT_SUCCESS : SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose");
}

/* send list of supported public keys to 'client' */
static void
process_request_identities(SocketEntry *e)
{
	Identity *id;
	struct sshbuf *msg, *keys;
	int r;
	u_int i = 0, nentries = 0;
	char *fp;

	debug2_f("entering");

	if ((msg = sshbuf_new()) == NULL || (keys = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if ((fp = sshkey_fingerprint(id->key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug_f("key %u / %u: %s %s", i++, idtab->nentries,
		    sshkey_ssh_name(id->key), fp);
		dump_dest_constraints(__func__,
		    id->dest_constraints, id->ndest_constraints);
		free(fp);
		/* identity not visible, don't include in response */
		if (identity_permitted(id, e, NULL, NULL, NULL) != 0)
			continue;
		if ((r = sshkey_puts_opts(id->key, keys,
		    SSHKEY_SERIALIZE_INFO)) != 0 ||
		    (r = sshbuf_put_cstring(keys, id->comment)) != 0) {
			error_fr(r, "compose key/comment");
			continue;
		}
		nentries++;
	}
	debug2_f("replying with %u allowed of %u available keys",
	    nentries, idtab->nentries);
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, nentries)) != 0 ||
	    (r = sshbuf_putb(msg, keys)) != 0)
		fatal_fr(r, "compose");
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");
	sshbuf_free(msg);
	sshbuf_free(keys);
}


static char *
agent_decode_alg(struct sshkey *key, u_int flags)
{
	if (key->type == KEY_RSA) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512";
	} else if (key->type == KEY_RSA_CERT) {
		if (flags & SSH_AGENT_RSA_SHA2_256)
			return "rsa-sha2-256-cert-v01@openssh.com";
		else if (flags & SSH_AGENT_RSA_SHA2_512)
			return "rsa-sha2-512-cert-v01@openssh.com";
	}
	return NULL;
}

/*
 * Attempt to parse the contents of a buffer as a SSH publickey userauth
 * request, checking its contents for consistency and matching the embedded
 * key against the one that is being used for signing.
 * Note: does not modify msg buffer.
 * Optionally extract the username, session ID and/or hostkey from the request.
 */
static int
parse_userauth_request(struct sshbuf *msg, const struct sshkey *expected_key,
    char **userp, struct sshbuf **sess_idp, struct sshkey **hostkeyp)
{
	struct sshbuf *b = NULL, *sess_id = NULL;
	char *user = NULL, *service = NULL, *method = NULL, *pkalg = NULL;
	int r;
	u_char t, sig_follows;
	struct sshkey *mkey = NULL, *hostkey = NULL;

	if (userp != NULL)
		*userp = NULL;
	if (sess_idp != NULL)
		*sess_idp = NULL;
	if (hostkeyp != NULL)
		*hostkeyp = NULL;
	if ((b = sshbuf_fromb(msg)) == NULL)
		fatal_f("sshbuf_fromb");

	/* SSH userauth request */
	if ((r = sshbuf_froms(b, &sess_id)) != 0)
		goto out;
	if (sshbuf_len(sess_id) == 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((r = sshbuf_get_u8(b, &t)) != 0 || /* SSH2_MSG_USERAUTH_REQUEST */
	    (r = sshbuf_get_cstring(b, &user, NULL)) != 0 || /* server user */
	    (r = sshbuf_get_cstring(b, &service, NULL)) != 0 || /* service */
	    (r = sshbuf_get_cstring(b, &method, NULL)) != 0 || /* method */
	    (r = sshbuf_get_u8(b, &sig_follows)) != 0 || /* sig-follows */
	    (r = sshbuf_get_cstring(b, &pkalg, NULL)) != 0 || /* alg */
	    (r = sshkey_froms(b, &mkey)) != 0) /* key */
		goto out;
	if (t != SSH2_MSG_USERAUTH_REQUEST ||
	    sig_follows != 1 ||
	    strcmp(service, "ssh-connection") != 0 ||
	    !sshkey_equal(expected_key, mkey) ||
	    sshkey_type_from_name(pkalg) != expected_key->type) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(method, "publickey-hostbound-v00@openssh.com") == 0) {
		if ((r = sshkey_froms(b, &hostkey)) != 0)
			goto out;
	} else if (strcmp(method, "publickey") != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
	debug3_f("well formed userauth");
	if (userp != NULL) {
		*userp = user;
		user = NULL;
	}
	if (sess_idp != NULL) {
		*sess_idp = sess_id;
		sess_id = NULL;
	}
	if (hostkeyp != NULL) {
		*hostkeyp = hostkey;
		hostkey = NULL;
	}
 out:
	sshbuf_free(b);
	sshbuf_free(sess_id);
	free(user);
	free(service);
	free(method);
	free(pkalg);
	sshkey_free(mkey);
	sshkey_free(hostkey);
	return r;
}

/*
 * Attempt to parse the contents of a buffer as a SSHSIG signature request.
 * Note: does not modify buffer.
 */
static int
parse_sshsig_request(struct sshbuf *msg)
{
	int r;
	struct sshbuf *b;

	if ((b = sshbuf_fromb(msg)) == NULL)
		fatal_f("sshbuf_fromb");

	if ((r = sshbuf_cmp(b, 0, "SSHSIG", 6)) != 0 ||
	    (r = sshbuf_consume(b, 6)) != 0 ||
	    (r = sshbuf_get_cstring(b, NULL, NULL)) != 0 || /* namespace */
	    (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0 || /* reserved */
	    (r = sshbuf_get_cstring(b, NULL, NULL)) != 0 || /* hashalg */
	    (r = sshbuf_get_string_direct(b, NULL, NULL)) != 0) /* H(msg) */
		goto out;
	if (sshbuf_len(b) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	return r;
}

/*
 * This function inspects a message to be signed by a FIDO key that has a
 * web-like application string (i.e. one that does not begin with "ssh:".
 * It checks that the message is one of those expected for SSH operations
 * (pubkey userauth, sshsig, CA key signing) to exclude signing challenges
 * for the web.
 */
static int
check_websafe_message_contents(struct sshkey *key, struct sshbuf *data)
{
	if (parse_userauth_request(data, key, NULL, NULL, NULL) == 0) {
		debug_f("signed data matches public key userauth request");
		return 1;
	}
	if (parse_sshsig_request(data) == 0) {
		debug_f("signed data matches SSHSIG signature request");
		return 1;
	}

	/* XXX check CA signature operation */

	error("web-origin key attempting to sign non-SSH message");
	return 0;
}

static int
buf_equal(const struct sshbuf *a, const struct sshbuf *b)
{
	if (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (sshbuf_len(a) != sshbuf_len(b))
		return SSH_ERR_INVALID_FORMAT;
	if (timingsafe_bcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		return SSH_ERR_INVALID_FORMAT;
	return 0;
}

/* ssh2 only */
static void
process_sign_request2(SocketEntry *e)
{
	u_char *signature = NULL;
	size_t slen = 0;
	u_int compat = 0, flags;
	int r, ok = -1, retried = 0;
	char *fp = NULL, *pin = NULL, *prompt = NULL;
	char *user = NULL, *sig_dest = NULL;
	const char *fwd_host = NULL, *dest_host = NULL;
	struct sshbuf *msg = NULL, *data = NULL, *sid = NULL;
	struct sshkey *key = NULL, *hostkey = NULL;
	struct identity *id;
	struct notifier_ctx *notifier = NULL;

	debug_f("entering");

	if ((msg = sshbuf_new()) == NULL || (data = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_get_stringb(e->request, data)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error_fr(r, "parse");
		goto send;
	}

	if ((id = lookup_identity(key)) == NULL) {
		verbose_f("%s key not found", sshkey_type(key));
		goto send;
	}
	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");

	if (id->ndest_constraints != 0) {
		if (e->nsession_ids == 0) {
			logit_f("refusing use of destination-constrained key "
			    "to sign on unbound connection");
			goto send;
		}
		if (parse_userauth_request(data, key, &user, &sid,
		    &hostkey) != 0) {
			logit_f("refusing use of destination-constrained key "
			   "to sign an unidentified signature");
			goto send;
		}
		/* XXX logspam */
		debug_f("user=%s", user);
		if (identity_permitted(id, e, user, &fwd_host, &dest_host) != 0)
			goto send;
		/* XXX display fwd_host/dest_host in askpass UI */
		/*
		 * Ensure that the session ID is the most recent one
		 * registered on the socket - it should have been bound by
		 * ssh immediately before userauth.
		 */
		if (buf_equal(sid,
		    e->session_ids[e->nsession_ids - 1].sid) != 0) {
			error_f("unexpected session ID (%zu listed) on "
			    "signature request for target user %s with "
			    "key %s %s", e->nsession_ids, user,
			    sshkey_type(id->key), fp);
			goto send;
		}
		/*
		 * Ensure that the hostkey embedded in the signature matches
		 * the one most recently bound to the socket. An exception is
		 * made for the initial forwarding hop.
		 */
		if (e->nsession_ids > 1 && hostkey == NULL) {
			error_f("refusing use of destination-constrained key: "
			    "no hostkey recorded in signature for forwarded "
			    "connection");
			goto send;
		}
		if (hostkey != NULL && !sshkey_equal(hostkey,
		    e->session_ids[e->nsession_ids - 1].key)) {
			error_f("refusing use of destination-constrained key: "
			    "mismatch between hostkey in request and most "
			    "recently bound session");
			goto send;
		}
		xasprintf(&sig_dest, "public key authentication request for "
		    "user \"%s\" to listed host", user);
	}
	if (id->confirm && confirm_key(id, sig_dest) != 0) {
		verbose_f("user refused key");
		goto send;
	}
	if (sshkey_is_sk(id->key)) {
		if (restrict_websafe &&
		    strncmp(id->key->sk_application, "ssh:", 4) != 0 &&
		    !check_websafe_message_contents(key, data)) {
			/* error already logged */
			goto send;
		}
		if (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD) {
			notifier = notify_start(0,
			    "Confirm user presence for key %s %s%s%s",
			    sshkey_type(id->key), fp,
			    sig_dest == NULL ? "" : "\n",
			    sig_dest == NULL ? "" : sig_dest);
		}
	}
 retry_pin:
	if ((r = sshkey_sign(id->key, &signature, &slen,
	    sshbuf_ptr(data), sshbuf_len(data), agent_decode_alg(key, flags),
	    id->sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		if (pin == NULL && !retried && sshkey_is_sk(id->key) &&
		    r == SSH_ERR_KEY_WRONG_PASSPHRASE) {
			notify_complete(notifier, NULL);
			notifier = NULL;
			/* XXX include sig_dest */
			xasprintf(&prompt, "Enter PIN%sfor %s key %s: ",
			    (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD) ?
			    " and confirm user presence " : " ",
			    sshkey_type(id->key), fp);
			pin = read_passphrase(prompt, RP_USE_ASKPASS);
			retried = 1;
			goto retry_pin;
		}
		error_fr(r, "sshkey_sign");
		goto send;
	}
	/* Success */
	ok = 0;
	debug_f("good signature");
 send:
	notify_complete(notifier, "User presence confirmed");

	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal_fr(r, "compose");
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal_fr(r, "compose failure");

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "enqueue");

	sshbuf_free(sid);
	sshbuf_free(data);
	sshbuf_free(msg);
	sshkey_free(key);
	sshkey_free(hostkey);
	free(fp);
	free(signature);
	free(sig_dest);
	free(user);
	free(prompt);
	if (pin != NULL)
		freezero(pin, strlen(pin));
}

/* shared */
static void
process_remove_identity(SocketEntry *e)
{
	int r, success = 0;
	struct sshkey *key = NULL;
	Identity *id;

	debug2_f("entering");
	if ((r = sshkey_froms(e->request, &key)) != 0) {
		error_fr(r, "parse key");
		goto done;
	}
	if ((id = lookup_identity(key)) == NULL) {
		debug_f("key not found");
		goto done;
	}
	/* identity not visible, cannot be removed */
	if (identity_permitted(id, e, NULL, NULL, NULL) != 0)
		goto done; /* error already logged */
	/* We have this key, free it. */
	if (idtab->nentries < 1)
		fatal_f("internal error: nentries %d", idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	success = 1;
 done:
	sshkey_free(key);
	send_status(e, success);
}

static void
process_remove_all_identities(SocketEntry *e)
{
	Identity *id;

	debug2_f("entering");
	/* Loop over all identities and clear the keys. */
	for (id = TAILQ_FIRST(&idtab->idlist); id;
	    id = TAILQ_FIRST(&idtab->idlist)) {
		TAILQ_REMOVE(&idtab->idlist, id, next);
		free_identity(id);
	}

	/* Mark that there are no identities. */
	idtab->nentries = 0;

	/* Send success. */
	send_status(e, 1);
}

/* removes expired keys and returns number of seconds until the next expiry */
static time_t
reaper(void)
{
	time_t deadline = 0, now = monotime();
	Identity *id, *nxt;

	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		if (id->death == 0)
			continue;
		if (now >= id->death) {
			debug("expiring key '%s'", id->comment);
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		} else
			deadline = (deadline == 0) ? id->death :
			    MINIMUM(deadline, id->death);
	}
	if (deadline == 0 || deadline <= now)
		return 0;
	else
		return (deadline - now);
}

static int
parse_dest_constraint_hop(struct sshbuf *b, struct dest_constraint_hop *dch)
{
	u_char key_is_ca;
	size_t elen = 0;
	int r;
	struct sshkey *k = NULL;
	char *fp;

	memset(dch, '\0', sizeof(*dch));
	if ((r = sshbuf_get_cstring(b, &dch->user, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(b, &dch->hostname, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, NULL, &elen)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	if (*dch->hostname == '\0') {
		free(dch->hostname);
		dch->hostname = NULL;
	}
	if (*dch->user == '\0') {
		free(dch->user);
		dch->user = NULL;
	}
	while (sshbuf_len(b) != 0) {
		dch->keys = xrecallocarray(dch->keys, dch->nkeys,
		    dch->nkeys + 1, sizeof(*dch->keys));
		dch->key_is_ca = xrecallocarray(dch->key_is_ca, dch->nkeys,
		    dch->nkeys + 1, sizeof(*dch->key_is_ca));
		if ((r = sshkey_froms(b, &k)) != 0 ||
		    (r = sshbuf_get_u8(b, &key_is_ca)) != 0)
			goto out;
		if ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal_f("fingerprint failed");
		debug3_f("%s%s%s: adding %skey %s %s",
		    dch->user == NULL ? "" : dch->user,
		    dch->user == NULL ? "" : "@",
		    dch->hostname, key_is_ca ? "CA " : "", sshkey_type(k), fp);
		free(fp);
		dch->keys[dch->nkeys] = k;
		dch->key_is_ca[dch->nkeys] = key_is_ca != 0;
		dch->nkeys++;
		k = NULL; /* transferred */
	}
	/* success */
	r = 0;
 out:
	sshkey_free(k);
	return r;
}

static int
parse_dest_constraint(struct sshbuf *m, struct dest_constraint *dc)
{
	struct sshbuf *b = NULL, *frombuf = NULL, *tobuf = NULL;
	int r;
	size_t elen = 0;

	debug3_f("entering");

	memset(dc, '\0', sizeof(*dc));
	if ((r = sshbuf_froms(m, &b)) != 0 ||
	    (r = sshbuf_froms(b, &frombuf)) != 0 ||
	    (r = sshbuf_froms(b, &tobuf)) != 0 ||
	    (r = sshbuf_get_string_direct(b, NULL, &elen)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if ((r = parse_dest_constraint_hop(frombuf, &dc->from)) != 0 ||
	    (r = parse_dest_constraint_hop(tobuf, &dc->to)) != 0)
		goto out; /* already logged */
	if (elen != 0) {
		error_f("unsupported extensions (len %zu)", elen);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	debug2_f("parsed %s (%u keys) > %s%s%s (%u keys)",
	    dc->from.hostname ? dc->from.hostname : "(ORIGIN)", dc->from.nkeys,
	    dc->to.user ? dc->to.user : "", dc->to.user ? "@" : "",
	    dc->to.hostname ? dc->to.hostname : "(ANY)", dc->to.nkeys);
	/* check consistency */
	if ((dc->from.hostname == NULL) != (dc->from.nkeys == 0) ||
	    dc->from.user != NULL) {
		error_f("inconsistent \"from\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (dc->to.hostname == NULL || dc->to.nkeys == 0) {
		error_f("incomplete \"to\" specification");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(frombuf);
	sshbuf_free(tobuf);
	return r;
}

static int
parse_key_constraint_extension(struct sshbuf *m, char **sk_providerp,
    struct dest_constraint **dcsp, size_t *ndcsp, int *cert_onlyp,
    struct sshkey ***certs, size_t *ncerts)
{
	char *ext_name = NULL;
	int r;
	struct sshbuf *b = NULL;
	u_char v;
	struct sshkey *k;

	if ((r = sshbuf_get_cstring(m, &ext_name, NULL)) != 0) {
		error_fr(r, "parse constraint extension");
		goto out;
	}
	debug_f("constraint ext %s", ext_name);
	if (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
		if (sk_providerp == NULL) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (*sk_providerp != NULL) {
			error_f("%s already set", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if ((r = sshbuf_get_cstring(m, sk_providerp, NULL)) != 0) {
			error_fr(r, "parse %s", ext_name);
			goto out;
		}
	} else if (strcmp(ext_name,
	    "restrict-destination-v00@openssh.com") == 0) {
		if (*dcsp != NULL) {
			error_f("%s already set", ext_name);
			goto out;
		}
		if ((r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s outer", ext_name);
			goto out;
		}
		while (sshbuf_len(b) != 0) {
			if (*ndcsp >= AGENT_MAX_DEST_CONSTRAINTS) {
				error_f("too many %s constraints", ext_name);
				goto out;
			}
			*dcsp = xrecallocarray(*dcsp, *ndcsp, *ndcsp + 1,
			    sizeof(**dcsp));
			if ((r = parse_dest_constraint(b,
			    *dcsp + (*ndcsp)++)) != 0)
				goto out; /* error already logged */
		}
	} else if (strcmp(ext_name,
	    "associated-certs-v00@openssh.com") == 0) {
		if (certs == NULL || ncerts == NULL || cert_onlyp == NULL) {
			error_f("%s not valid here", ext_name);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		if (*certs != NULL) {
			error_f("%s already set", ext_name);
			goto out;
		}
		if ((r = sshbuf_get_u8(m, &v)) != 0 ||
		    (r = sshbuf_froms(m, &b)) != 0) {
			error_fr(r, "parse %s", ext_name);
			goto out;
		}
		*cert_onlyp = v != 0;
		while (sshbuf_len(b) != 0) {
			if (*ncerts >= AGENT_MAX_EXT_CERTS) {
				error_f("too many %s constraints", ext_name);
				goto out;
			}
			*certs = xrecallocarray(*certs, *ncerts, *ncerts + 1,
			    sizeof(**certs));
			if ((r = sshkey_froms(b, &k)) != 0) {
				error_fr(r, "parse key");
				goto out;
			}
			(*certs)[(*ncerts)++] = k;
		}
	} else {
		error_f("unsupported constraint \"%s\"", ext_name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(ext_name);
	sshbuf_free(b);
	return r;
}

static int
parse_key_constraints(struct sshbuf *m, struct sshkey *k, time_t *deathp,
    u_int *secondsp, int *confirmp, char **sk_providerp,
    struct dest_constraint **dcsp, size_t *ndcsp,
    int *cert_onlyp, size_t *ncerts, struct sshkey ***certs)
{
	u_char ctype;
	int r;
	u_int seconds, maxsign = 0;

	while (sshbuf_len(m)) {
		if ((r = sshbuf_get_u8(m, &ctype)) != 0) {
			error_fr(r, "parse constraint type");
			goto out;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_LIFETIME:
			if (*deathp != 0) {
				error_f("lifetime already set");
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			if ((r = sshbuf_get_u32(m, &seconds)) != 0) {
				error_fr(r, "parse lifetime constraint");
				goto out;
			}
			*deathp = monotime() + seconds;
			*secondsp = seconds;
			break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			if (*confirmp != 0) {
				error_f("confirm already set");
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			*confirmp = 1;
			break;
		case SSH_AGENT_CONSTRAIN_MAXSIGN:
			if (k == NULL) {
				error_f("maxsign not valid here");
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			if (maxsign != 0) {
				error_f("maxsign already set");
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			if ((r = sshbuf_get_u32(m, &maxsign)) != 0) {
				error_fr(r, "parse maxsign constraint");
				goto out;
			}
			if ((r = sshkey_enable_maxsign(k, maxsign)) != 0) {
				error_fr(r, "enable maxsign");
				goto out;
			}
			break;
		case SSH_AGENT_CONSTRAIN_EXTENSION:
			if ((r = parse_key_constraint_extension(m,
			    sk_providerp, dcsp, ndcsp,
			    cert_onlyp, certs, ncerts)) != 0)
				goto out; /* error already logged */
			break;
		default:
			error_f("Unknown constraint %d", ctype);
			r = SSH_ERR_FEATURE_UNSUPPORTED;
			goto out;
		}
	}
	/* success */
	r = 0;
 out:
	return r;
}

static void
process_add_identity(SocketEntry *e)
{
	Identity *id;
	int success = 0, confirm = 0;
	char *fp, *comment = NULL, *sk_provider = NULL;
	char canonical_provider[PATH_MAX];
	time_t death = 0;
	u_int seconds = 0;
	struct dest_constraint *dest_constraints = NULL;
	size_t ndest_constraints = 0;
	struct sshkey *k = NULL;
	int r = SSH_ERR_INTERNAL_ERROR;

	debug2_f("entering");
	if ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == NULL ||
	    (r = sshbuf_get_cstring(e->request, &comment, NULL)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if (parse_key_constraints(e->request, k, &death, &seconds, &confirm,
	    &sk_provider, &dest_constraints, &ndest_constraints,
	    NULL, NULL, NULL) != 0) {
		error_f("failed to parse constraints");
		sshbuf_reset(e->request);
		goto out;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);

	if (sk_provider != NULL) {
		if (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			goto out;
		}
		if (strcasecmp(sk_provider, "internal") == 0) {
			debug_f("internal provider");
		} else {
			if (socket_is_remote(e) && !remote_add_provider) {
				verbose("failed add of SK provider \"%.100s\": "
				    "remote addition of providers is disabled",
				    sk_provider);
				goto out;
			}
			if (realpath(sk_provider, canonical_provider) == NULL) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				goto out;
			}
			free(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			if (match_pattern_list(sk_provider,
			    allowed_providers, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not allowed", sk_provider);
				goto out;
			}
		}
	}
	if ((r = sshkey_shield_private(k)) != 0) {
		error_fr(r, "shield private");
		goto out;
	}
	if (lifetime && !death)
		death = monotime() + lifetime;
	if ((id = lookup_identity(k)) == NULL) {
		id = xcalloc(1, sizeof(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} else {
		/* identity not visible, do not update */
		if (identity_permitted(id, e, NULL, NULL, NULL) != 0)
			goto out; /* error already logged */
		/* key state might have been updated */
		sshkey_free(id->key);
		free(id->comment);
		free(id->sk_provider);
		free_dest_constraints(id->dest_constraints,
		    id->ndest_constraints);
	}
	/* success */
	id->key = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;
	id->dest_constraints = dest_constraints;
	id->ndest_constraints = ndest_constraints;

	if ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("sshkey_fingerprint failed");
	debug_f("add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s) (destination constraints: %zu)",
	    sshkey_ssh_name(k), fp, comment, seconds, confirm,
	    sk_provider == NULL ? "none" : sk_provider, ndest_constraints);
	free(fp);
	/* transferred */
	k = NULL;
	comment = NULL;
	sk_provider = NULL;
	dest_constraints = NULL;
	ndest_constraints = 0;
	success = 1;
 out:
	free(sk_provider);
	free(comment);
	sshkey_free(k);
	free_dest_constraints(dest_constraints, ndest_constraints);
	send_status(e, success);
}

/* XXX todo: encrypt sensitive data with passphrase */
static void
process_lock_agent(SocketEntry *e, int lock)
{
	int r, success = 0, delay;
	char *passwd;
	u_char passwdhash[LOCK_SIZE];
	static u_int fail_count = 0;
	size_t pwlen;

	debug2_f("entering");
	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal_fr(r, "parse");
	if (pwlen == 0) {
		debug("empty password not supported");
	} else if (locked && !lock) {
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt),
		    passwdhash, sizeof(passwdhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		if (timingsafe_bcmp(passwdhash, lock_pwhash, LOCK_SIZE) == 0) {
			debug("agent unlocked");
			locked = 0;
			fail_count = 0;
			explicit_bzero(lock_pwhash, sizeof(lock_pwhash));
			success = 1;
		} else {
			/* delay in 0.1s increments up to 10s */
			if (fail_count < 100)
				fail_count++;
			delay = 100000 * fail_count;
			debug("unlock failed, delaying %0.1lf seconds",
			    (double)delay/1000000);
			usleep(delay);
		}
		explicit_bzero(passwdhash, sizeof(passwdhash));
	} else if (!locked && lock) {
		debug("agent locked");
		locked = 1;
		arc4random_buf(lock_salt, sizeof(lock_salt));
		if (bcrypt_pbkdf(passwd, pwlen, lock_salt, sizeof(lock_salt),
		    lock_pwhash, sizeof(lock_pwhash), LOCK_ROUNDS) < 0)
			fatal("bcrypt_pbkdf");
		success = 1;
	}
	freezero(passwd, pwlen);
	send_status(e, success);
}

static void
no_identities(SocketEntry *e)
{
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal_fr(r, "compose");
	sshbuf_free(msg);
}

#ifdef ENABLE_PKCS11
/* Add an identity to idlist; takes ownership of 'key' and 'comment' */
static void
add_p11_identity(struct sshkey *key, char *comment, const char *provider,
    time_t death, u_int confirm, struct dest_constraint *dest_constraints,
    size_t ndest_constraints)
{
	Identity *id;

	if (lookup_identity(key) != NULL) {
		sshkey_free(key);
		free(comment);
		return;
	}
	id = xcalloc(1, sizeof(Identity));
	id->key = key;
	id->comment = comment;
	id->provider = xstrdup(provider);
	id->death = death;
	id->confirm = confirm;
	id->dest_constraints = dup_dest_constraints(dest_constraints,
	    ndest_constraints);
	id->ndest_constraints = ndest_constraints;
	TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
	idtab->nentries++;
}

static void
process_add_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	char **comments = NULL;
	int r, i, count = 0, success = 0, confirm = 0;
	u_int seconds = 0;
	time_t death = 0;
	struct sshkey **keys = NULL, *k;
	struct dest_constraint *dest_constraints = NULL;
	size_t j, ndest_constraints = 0, ncerts = 0;
	struct sshkey **certs = NULL;
	int cert_only = 0;

	debug2_f("entering");
	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	if (parse_key_constraints(e->request, NULL, &death, &seconds, &confirm,
	    NULL, &dest_constraints, &ndest_constraints, &cert_only,
	    &ncerts, &certs) != 0) {
		error_f("failed to parse constraints");
		goto send;
	}
	dump_dest_constraints(__func__, dest_constraints, ndest_constraints);
	if (socket_is_remote(e) && !remote_add_provider) {
		verbose("failed PKCS#11 add of \"%.100s\": remote addition of "
		    "providers is disabled", provider);
		goto send;
	}
	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}
	if (match_pattern_list(canonical_provider, allowed_providers, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not allowed", canonical_provider);
		goto send;
	}
	debug_f("add %.100s", canonical_provider);
	if (lifetime && !death)
		death = monotime() + lifetime;

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &comments);
	for (i = 0; i < count; i++) {
		if (comments[i] == NULL || comments[i][0] == '\0') {
			free(comments[i]);
			comments[i] = xstrdup(canonical_provider);
		}
		for (j = 0; j < ncerts; j++) {
			if (!sshkey_is_cert(certs[j]))
				continue;
			if (!sshkey_equal_public(keys[i], certs[j]))
				continue;
			if (pkcs11_make_cert(keys[i], certs[j], &k) != 0)
				continue;
			add_p11_identity(k, xstrdup(comments[i]),
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			success = 1;
		}
		if (!cert_only && lookup_identity(keys[i]) == NULL) {
			add_p11_identity(keys[i], comments[i],
			    canonical_provider, death, confirm,
			    dest_constraints, ndest_constraints);
			keys[i] = NULL;		/* transferred */
			comments[i] = NULL;	/* transferred */
			success = 1;
		}
		/* XXX update constraints for existing keys */
		sshkey_free(keys[i]);
		free(comments[i]);
	}
send:
	free(pin);
	free(provider);
	free(keys);
	free(comments);
	free_dest_constraints(dest_constraints, ndest_constraints);
	for (j = 0; j < ncerts; j++)
		sshkey_free(certs[j]);
	free(certs);
	send_status(e, success);
}

static void
process_remove_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, success = 0;
	Identity *id, *nxt;

	debug2_f("entering");
	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error_fr(r, "parse");
		goto send;
	}
	free(pin);

	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}

	debug_f("remove %.100s", canonical_provider);
	for (id = TAILQ_FIRST(&idtab->idlist); id; id = nxt) {
		nxt = TAILQ_NEXT(id, next);
		/* Skip file--based keys */
		if (id->provider == NULL)
			continue;
		if (!strcmp(canonical_provider, id->provider)) {
			TAILQ_REMOVE(&idtab->idlist, id, next);
			free_identity(id);
			idtab->nentries--;
		}
	}
	if (pkcs11_del_provider(canonical_provider) == 0)
		success = 1;
	else
		error_f("pkcs11_del_provider failed");
send:
	free(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

static void
process_ext_session_bind(SocketEntry *e, struct sshbuf *buf)
{
	int r, sid_match, key_match;
	struct sshkey *key = NULL;
	struct sshbuf *sid = NULL, *sig = NULL, *msg = NULL;
	char *fp = NULL;
	size_t i;
	u_char fwd = 0;

	(void)buf;

	debug2_f("entering");
	e->session_bind_attempted = 1;
	if ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_froms(e->request, &sid)) != 0 ||
	    (r = sshbuf_froms(e->request, &sig)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &fwd)) != 0) {
		error_fr(r, "parse");
		goto out;
	}
	if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal_f("fingerprint failed");
	/* check signature with hostkey on session ID */
	if ((r = sshkey_verify(key, sshbuf_ptr(sig), sshbuf_len(sig),
	    sshbuf_ptr(sid), sshbuf_len(sid), NULL, 0, NULL)) != 0) {
		error_fr(r, "sshkey_verify for %s %s", sshkey_type(key), fp);
		goto out;
	}
	/* check whether sid/key already recorded */
	for (i = 0; i < e->nsession_ids; i++) {
		if (!e->session_ids[i].forwarded) {
			error_f("attempt to bind session ID to socket "
			    "previously bound for authentication attempt");
			r = -1;
			goto out;
		}
		sid_match = buf_equal(sid, e->session_ids[i].sid) == 0;
		key_match = sshkey_equal(key, e->session_ids[i].key);
		if (sid_match && key_match) {
			debug_f("session ID already recorded for %s %s",
			    sshkey_type(key), fp);
			r = 0;
			goto out;
		} else if (sid_match) {
			error_f("session ID recorded against different key "
			    "for %s %s", sshkey_type(key), fp);
			r = -1;
			goto out;
		}
		/*
		 * new sid with previously-seen key can happen, e.g. multiple
		 * connections to the same host.
		 */
	}
	/* record new key/sid */
	if (e->nsession_ids >= AGENT_MAX_SESSION_IDS) {
		error_f("too many session IDs recorded");
		goto out;
	}
	e->session_ids = xrecallocarray(e->session_ids, e->nsession_ids,
	    e->nsession_ids + 1, sizeof(*e->session_ids));
	i = e->nsession_ids++;
	debug_f("recorded %s %s (slot %zu of %d)", sshkey_type(key), fp, i,
	    AGENT_MAX_SESSION_IDS);
	e->session_ids[i].key = key;
	e->session_ids[i].forwarded = fwd != 0;
	key = NULL; /* transferred */
	/* can't transfer sid; it's refcounted and scoped to request's life */
	if ((e->session_ids[i].sid = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if ((r = sshbuf_putb(e->session_ids[i].sid, sid)) != 0)
		fatal_fr(r, "sshbuf_putb session ID");
	/* success */
	r = 0;
 out:
	free(fp);
	sshkey_free(key);
	sshbuf_free(sid);
	sshbuf_free(sig);
	if ((msg = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new");
	if (r == 0) {
		if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_EXT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}



static void
process_ext_ecdh(SocketEntry *e, struct sshbuf *buf)
{
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct sshkey *partner = NULL;
	struct identity *id;
	u_char *secret = NULL;
	size_t seclen = 0, fieldsz;
	u_int flags;
	int r, ok = -1;
	int was_shielded;
	const EC_KEY *eck, *epheck;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(buf, &key)) ||
	    (r = sshkey_froms(buf, &partner))) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}
	if ((r = sshbuf_get_u32(buf, &flags))) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}

	if (flags != 0) {
		error("%s: invalid flags: %u", __func__, flags);
		goto send;
	}

	if ((id = lookup_identity(key)) == NULL) {
		verbose("%s: %s key not found", __func__, sshkey_type(key));
		goto send;
	}
	if (id->confirm && confirm_key(id, NULL) != 0) {
		verbose("%s: user refused key", __func__);
		goto send;
	}
	if (sshkey_is_sk(id->key)) {
		verbose("%s: not supported for sk keys", __func__);
		goto send;
	}
	if (id->key->type != KEY_ECDSA || id->key->pkey == NULL) {
		verbose("%s: not an ecdsa key", __func__);
		goto send;
	}
	if (id->key->ecdsa_nid != partner->ecdsa_nid) {
		verbose("%s: curve mismatch", __func__);
		goto send;
	}

	eck = EVP_PKEY_get1_EC_KEY(id->key->pkey);
	epheck = EVP_PKEY_get1_EC_KEY(partner->pkey);

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(eck));
	seclen = (fieldsz + 7) / 8;
	secret = calloc(1, seclen);
	if (secret == NULL)
		fatal("%s: failed to allocate memory", __func__);

	was_shielded = sshkey_is_shielded(id->key);
	if ((r = sshkey_unshield_private(id->key)) != 0) {
		verbose("%s: failed to unshield: %s", __func__, ssh_err(r));
		goto send;
	}

	/* fetch this again in case unshield changed it */
	eck = EVP_PKEY_get1_EC_KEY(id->key->pkey);

	r = ECDH_compute_key(secret, seclen,
	    EC_KEY_get0_public_key(epheck), eck, NULL);
	if (was_shielded)
		sshkey_shield_private(id->key);
	if (r <= 0) {
		error("%s: openssl error: %d", __func__, r);
		goto send;
	}
	seclen = (size_t)r;

	ok = 0;

send:
	sshkey_free(key);
	sshkey_free(partner);
	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
		    (r = sshbuf_put_string(msg, secret, seclen)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_EXT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
	if (seclen > 0)
		explicit_bzero(secret, seclen);
	free(secret);
}

static void
process_ext_ecdh_rebox(SocketEntry *e, struct sshbuf *buf)
{
	struct sshbuf *msg, *boxbuf = NULL, *guidb = NULL;
	struct sshkey *partner = NULL;
	struct identity *id;
	uint8_t slotid;
	u_int flags;
	int r, ok = -1;
	struct piv_ecdh_box *box = NULL, *newbox = NULL;
	uint8_t *secret = NULL, *out = NULL;
	size_t seclen = 0, outlen = 0;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_froms(buf, &boxbuf)) != 0 ||
	    (r = sshbuf_froms(buf, &guidb)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}
	if ((r = sshbuf_get_u8(buf, &slotid)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}
	if ((r = sshkey_froms(buf, &partner))) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}
	if ((r = sshbuf_get_u32(buf, &flags))) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}

	if (flags != 0) {
		error("%s: invalid flags: %u", __func__, flags);
		goto send;
	}

	if ((r = sshbuf_get_piv_box(boxbuf, &box)) != 0) {
		verbose("%s: failed to parse box: %s", __func__, ssh_err(r));
		goto send;
	}

	if ((id = lookup_identity(box->pdb_pub)) == NULL) {
		verbose("%s: %s key not found", __func__,
		    sshkey_type(box->pdb_pub));
		goto send;
	}
	if (id->confirm && confirm_key(id, NULL) != 0) {
		verbose("%s: user refused key", __func__);
		goto send;
	}
	if (sshkey_is_sk(id->key)) {
		verbose("%s: not supported for sk keys", __func__);
		goto send;
	}
	if (id->key->type != KEY_ECDSA || id->key->pkey == NULL) {
		verbose("%s: not an ecdsa key", __func__);
		goto send;
	}
	if (id->key->ecdsa_nid != partner->ecdsa_nid) {
		verbose("%s: curve mismatch", __func__);
		goto send;
	}

	if ((r = piv_box_open_offline(id->key, box)) != 0) {
		verbose("%s: failed to open box: %s", __func__, ssh_err(r));
		goto send;
	}

	if ((r = piv_box_take_data(box, &secret, &seclen)) != 0) {
		verbose("%s: failed to take data: %s", __func__, ssh_err(r));
		goto send;
	}

	newbox = piv_box_new();
	if (newbox == NULL) {
		fatal("%s: failed to allocate memory", __func__);
	}

	if (sshbuf_len(guidb) == sizeof (box->pdb_guid)) {
		bcopy(sshbuf_ptr(guidb), box->pdb_guid, sizeof (box->pdb_guid));
		box->pdb_slot = slotid;
		box->pdb_guidslot_valid = 1;
	}
	piv_box_set_data(newbox, secret, seclen);
	if ((r = piv_box_seal_offline(partner, newbox)) != 0) {
		verbose("%s: failed to seal box: %s", __func__, ssh_err(r));
		goto send;
	}

	if ((r = piv_box_to_binary(newbox, &out, &outlen)) != 0) {
		verbose("%s: failed to pack box: %s", __func__, ssh_err(r));
		goto send;
	}

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_string(msg, out, outlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	ok = 0;

send:
	sshkey_free(partner);
	piv_box_free(box);
	piv_box_free(newbox);
	freezero(secret, seclen);
	freezero(out, outlen);
	sshbuf_free(boxbuf);
	sshbuf_free(guidb);
	if (ok != 0) {
		if ((r = sshbuf_put_u8(msg, SSH_AGENT_EXT_FAILURE)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
}

struct exthandler {
	const char 	*eh_name;
	int		 eh_string;
	void (*eh_handler)(SocketEntry *, struct sshbuf *);
};
struct exthandler exthandlers[];

static void
process_ext_query(SocketEntry *e, struct sshbuf *buf)
{
	int r, n = 0;
	struct exthandler *h;
	struct sshbuf *msg;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	for (h = exthandlers; h->eh_name != NULL; ++h)
		++n;

	if ((r = sshbuf_put_u8(msg, SSH_AGENT_SUCCESS)) != 0 ||
	    (r = sshbuf_put_u32(msg, n)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	for (h = exthandlers; h->eh_name != NULL; ++h) {
		if ((r = sshbuf_put_cstring(msg, h->eh_name)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}

struct exthandler exthandlers[] = {
	{ "query", 			0,	process_ext_query },
	{ "session-bind@openssh.com",	0,	process_ext_session_bind },
	{ "ecdh@joyent.com",		1,	process_ext_ecdh },
	{ "ecdh-rebox@joyent.com",	1,	process_ext_ecdh_rebox },
	{ NULL, 0, NULL }
};

static void
process_extension(SocketEntry *e)
{
	int r;
	char *extname = NULL;
	size_t enlen;
	struct sshbuf *inner = NULL;
	struct exthandler *h, *hdlr = NULL;

	if ((r = sshbuf_get_cstring(e->request, &extname, &enlen))) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto err;
	}

	for (h = exthandlers; h->eh_name != NULL; ++h) {
		if (strcmp(h->eh_name, extname) == 0) {
			hdlr = h;
			break;
		}
	}
	if (hdlr == NULL) {
		error("%s: requested unknown ext %s", __func__, extname);
		goto err;
	}

	if (hdlr->eh_string) {
		if ((r = sshbuf_froms(e->request, &inner))) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto err;
		}
	} else {
		inner = e->request;
	}

	hdlr->eh_handler(e, inner);
	goto out;
err:
	sshbuf_reset(e->request);
	send_status(e, 0);
out:
	if (hdlr->eh_string)
		sshbuf_free(inner);
	free(extname);
}

/*
 * dispatch incoming message.
 * returns 1 on success, 0 for incomplete messages or -1 on error.
 */
static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	SocketEntry *e;

	if (socknum >= sockets_alloc)
		fatal_f("sock %u >= allocated %u", socknum, sockets_alloc);
	e = &sockets[socknum];

	if (sshbuf_len(e->input) < 5)
		return 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		debug_f("socket %u (fd=%d) message too long %u > %u",
		    socknum, e->fd, msg_len, AGENT_MAX_LEN);
		return -1;
	}
	if (sshbuf_len(e->input) < msg_len + 4)
		return 0;		/* Incomplete message body. */

	/* move the current input to e->request */
	sshbuf_reset(e->request);
	if ((r = sshbuf_get_stringb(e->input, e->request)) != 0 ||
	    (r = sshbuf_get_u8(e->request, &type)) != 0) {
		if (r == SSH_ERR_MESSAGE_INCOMPLETE ||
		    r == SSH_ERR_STRING_TOO_LARGE) {
			error_fr(r, "parse");
			return -1;
		}
		fatal_fr(r, "parse");
	}

	debug_f("socket %u (fd=%d) type %d", socknum, e->fd, type);

	/* check whether agent is locked */
	if (locked && type != SSH_AGENTC_UNLOCK) {
		sshbuf_reset(e->request);
		switch (type) {
		case SSH2_AGENTC_REQUEST_IDENTITIES:
			/* send empty lists */
			no_identities(e);
			break;
		default:
			/* send a fail message for all other request types */
			send_status(e, 0);
		}
		return 1;
	}

	switch (type) {
	case SSH_AGENTC_LOCK:
	case SSH_AGENTC_UNLOCK:
		process_lock_agent(e, type == SSH_AGENTC_LOCK);
		break;
	case SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES:
		process_remove_all_identities(e); /* safe for !WITH_SSH1 */
		break;
	/* ssh2 */
	case SSH2_AGENTC_SIGN_REQUEST:
		process_sign_request2(e);
		break;
	case SSH2_AGENTC_REQUEST_IDENTITIES:
		process_request_identities(e);
		break;
	case SSH2_AGENTC_ADD_IDENTITY:
	case SSH2_AGENTC_ADD_ID_CONSTRAINED:
		process_add_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_IDENTITY:
		process_remove_identity(e);
		break;
	case SSH2_AGENTC_REMOVE_ALL_IDENTITIES:
		process_remove_all_identities(e);
		break;
#ifdef ENABLE_PKCS11
	case SSH_AGENTC_ADD_SMARTCARD_KEY:
	case SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED:
		process_add_smartcard_key(e);
		break;
	case SSH_AGENTC_REMOVE_SMARTCARD_KEY:
		process_remove_smartcard_key(e);
		break;
#endif /* ENABLE_PKCS11 */
	case SSH_AGENTC_EXTENSION:
		process_extension(e);
		break;
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 1;
}

static void
new_socket(sock_type type, int fd)
{
	u_int i, old_alloc, new_alloc;

	debug_f("type = %s", type == AUTH_CONNECTION ? "CONNECTION" :
	    (type == AUTH_SOCKET ? "SOCKET" : "UNKNOWN"));
	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			if ((sockets[i].input = sshbuf_new()) == NULL ||
			    (sockets[i].output = sshbuf_new()) == NULL ||
			    (sockets[i].request = sshbuf_new()) == NULL)
				fatal_f("sshbuf_new failed");
			sockets[i].type = type;
			return;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xrecallocarray(sockets, old_alloc, new_alloc,
	    sizeof(sockets[0]));
	for (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	if ((sockets[old_alloc].input = sshbuf_new()) == NULL ||
	    (sockets[old_alloc].output = sshbuf_new()) == NULL ||
	    (sockets[old_alloc].request = sshbuf_new()) == NULL)
		fatal_f("sshbuf_new failed");
	sockets[old_alloc].type = type;
}

static int
handle_socket_read(u_int socknum)
{
	struct sockaddr_un sunaddr;
	socklen_t slen;
	uid_t euid;
	gid_t egid;
	int fd;

	slen = sizeof(sunaddr);
	fd = accept(sockets[socknum].fd, (struct sockaddr *)&sunaddr, &slen);
	if (fd == -1) {
		error("accept from AUTH_SOCKET: %s", strerror(errno));
		return -1;
	}
	if (getpeereid(fd, &euid, &egid) == -1) {
		error("getpeereid %d failed: %s", fd, strerror(errno));
		close(fd);
		return -1;
	}
	if (check_uid && (euid != 0) && (getuid() != euid)) {
		error("uid mismatch: peer euid %u != uid %u",
		    (u_int) euid, (u_int) getuid());
		close(fd);
		return -1;
	}
	new_socket(AUTH_CONNECTION, fd);
	return 0;
}

static int
handle_conn_read(u_int socknum)
{
	char buf[AGENT_RBUF_LEN];
	ssize_t len;
	int r;

	if ((len = read(sockets[socknum].fd, buf, sizeof(buf))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal_fr(r, "compose");
	explicit_bzero(buf, sizeof(buf));
	for (;;) {
		if ((r = process_message(socknum)) == -1)
			return -1;
		else if (r == 0)
			break;
	}
	return 0;
}

static int
handle_conn_write(u_int socknum)
{
	ssize_t len;
	int r;

	if (sshbuf_len(sockets[socknum].output) == 0)
		return 0; /* shouldn't happen */
	if ((len = write(sockets[socknum].fd,
	    sshbuf_ptr(sockets[socknum].output),
	    sshbuf_len(sockets[socknum].output))) <= 0) {
		if (len == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return 0;
			error_f("read error on socket %u (fd %d): %s",
			    socknum, sockets[socknum].fd, strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal_fr(r, "consume");
	return 0;
}

static void
after_poll(struct pollfd *pfd, size_t npfd, u_int maxfds)
{
	size_t i;
	u_int socknum, activefds = npfd;

	for (i = 0; i < npfd; i++) {
		if (pfd[i].revents == 0)
			continue;
		/* Find sockets entry */
		for (socknum = 0; socknum < sockets_alloc; socknum++) {
			if (sockets[socknum].type != AUTH_SOCKET &&
			    sockets[socknum].type != AUTH_CONNECTION)
				continue;
			if (pfd[i].fd == sockets[socknum].fd)
				break;
		}
		if (socknum >= sockets_alloc) {
			error_f("no socket for fd %d", pfd[i].fd);
			continue;
		}
		/* Process events */
		switch (sockets[socknum].type) {
		case AUTH_SOCKET:
			if ((pfd[i].revents & (POLLIN|POLLERR)) == 0)
				break;
			if (npfd > maxfds) {
				debug3("out of fds (active %u >= limit %u); "
				    "skipping accept", activefds, maxfds);
				break;
			}
			if (handle_socket_read(socknum) == 0)
				activefds++;
			break;
		case AUTH_CONNECTION:
			if ((pfd[i].revents & (POLLIN|POLLHUP|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0)
				goto close_sock;
			if ((pfd[i].revents & (POLLOUT|POLLHUP)) != 0 &&
			    handle_conn_write(socknum) != 0) {
 close_sock:
				if (activefds == 0)
					fatal("activefds == 0 at close_sock");
				close_socket(&sockets[socknum]);
				activefds--;
				break;
			}
			break;
		default:
			break;
		}
	}
}

static int
prepare_poll(struct pollfd **pfdp, size_t *npfdp, struct timespec *timeoutp, u_int maxfds)
{
	struct pollfd *pfd = *pfdp;
	size_t i, j, npfd = 0;
	time_t deadline;
	int r;

	/* Count active sockets */
	for (i = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
		case AUTH_CONNECTION:
			npfd++;
			break;
		case AUTH_UNUSED:
			break;
		default:
			fatal("Unknown socket type %d", sockets[i].type);
			break;
		}
	}
	if (npfd != *npfdp &&
	    (pfd = recallocarray(pfd, *npfdp, npfd, sizeof(*pfd))) == NULL)
		fatal_f("recallocarray failed");
	*pfdp = pfd;
	*npfdp = npfd;

	for (i = j = 0; i < sockets_alloc; i++) {
		switch (sockets[i].type) {
		case AUTH_SOCKET:
			if (npfd > maxfds) {
				debug3("out of fds (active %zu >= limit %u); "
				    "skipping arming listener", npfd, maxfds);
				break;
			}
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			pfd[j].events = POLLIN;
			j++;
			break;
		case AUTH_CONNECTION:
			pfd[j].fd = sockets[i].fd;
			pfd[j].revents = 0;
			/*
			 * Only prepare to read if we can handle a full-size
			 * input read buffer and enqueue a max size reply..
			 */
			if ((r = sshbuf_check_reserve(sockets[i].input,
			    AGENT_RBUF_LEN)) == 0 &&
			    (r = sshbuf_check_reserve(sockets[i].output,
			    AGENT_MAX_LEN)) == 0)
				pfd[j].events = POLLIN;
			else if (r != SSH_ERR_NO_BUFFER_SPACE)
				fatal_fr(r, "reserve");
			if (sshbuf_len(sockets[i].output) > 0)
				pfd[j].events |= POLLOUT;
			j++;
			break;
		default:
			break;
		}
	}
	deadline = reaper();
	if (parent_alive_interval != 0)
		deadline = (deadline == 0) ? parent_alive_interval :
		    MINIMUM(deadline, parent_alive_interval);
	if (deadline != 0)
		ptimeout_deadline_sec(timeoutp, deadline);
	return (1);
}

static void
cleanup_socket(void)
{
	if (cleanup_pid != 0 && getpid() != cleanup_pid)
		return;
	debug_f("cleanup");
	if (socket_name[0])
		unlink(socket_name);
	if (socket_dir[0])
		rmdir(socket_dir);
}

void
cleanup_exit(int i)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(i);
}

static void
cleanup_handler(int sig)
{
	signalled = sig;
}

static void
check_parent_exists(void)
{
	/*
	 * If our parent has exited then getppid() will return (pid_t)1,
	 * so testing for that should be safe.
	 */
	if (parent_pid != -1 && getppid() != parent_pid) {
		/* printf("Parent has died - Authentication agent exiting.\n"); */
		cleanup_socket();
		_exit(2);
	}
}

static void
usage(void)
{
	fprintf(stderr,
	    "usage: ssh-agent [-c | -s] [-DdU] [-a bind_address] [-E fingerprint_hash]\n"
	    "                 [-O option] [-P allowed_providers] [-t life]\n"
	    "       ssh-agent [-a bind_address] [-E fingerprint_hash] [-O option]\n"
	    "                 [-P allowed_providers] [-t life] command [arg ...]\n"
	    "       ssh-agent [-c | -s] -k\n");
	exit(1);
}

int
main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int sock, ch, result, saved_errno;
	char *shell, *format, *pidstr, *agentsocket = NULL;
#ifdef HAVE_SETRLIMIT
	struct rlimit rlim;
#endif
	extern int optind;
	extern char *optarg;
	pid_t pid;
	char pidstrbuf[1 + 3 * sizeof pid];
	size_t len;
	mode_t prev_mask;
	struct timespec timeout;
	struct pollfd *pfd = NULL;
	size_t npfd = 0;
	u_int maxfds;
	sigset_t nsigset, osigset;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	(void)setegid(getgid());
	(void)setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

#ifdef RLIMIT_NOFILE
	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	while ((ch = getopt(ac, av, "cDdksE:a:O:P:t:U")) != -1) {
		switch (ch) {
		case 'E':
			fingerprint_hash = ssh_digest_alg_by_name(optarg);
			if (fingerprint_hash == -1)
				fatal("Invalid hash algorithm \"%s\"", optarg);
			break;
		case 'c':
			if (s_flag)
				usage();
			c_flag++;
			break;
		case 'k':
			k_flag++;
			break;
		case 'O':
			if (strcmp(optarg, "no-restrict-websafe") == 0)
				restrict_websafe = 0;
			else if (strcmp(optarg, "allow-remote-pkcs11") == 0)
				remote_add_provider = 1;
			else
				fatal("Unknown -O option");
			break;
		case 'P':
			if (allowed_providers != NULL)
				fatal("-P option already specified");
			allowed_providers = xstrdup(optarg);
			break;
		case 's':
			if (c_flag)
				usage();
			s_flag++;
			break;
		case 'd':
			if (d_flag || D_flag)
				usage();
			d_flag++;
			break;
		case 'D':
			if (d_flag || D_flag)
				usage();
			D_flag++;
			break;
		case 'a':
			agentsocket = optarg;
			break;
		case 't':
			if ((lifetime = convtime(optarg)) == -1) {
				fprintf(stderr, "Invalid lifetime\n");
				usage();
			}
			break;
		case 'U':
			check_uid = 0;
			break;
		default:
			usage();
		}
	}
	ac -= optind;
	av += optind;

	if (ac > 0 && (c_flag || k_flag || s_flag || d_flag || D_flag))
		usage();

	if (allowed_providers == NULL)
		allowed_providers = xstrdup(DEFAULT_ALLOWED_PROVIDERS);

	if (ac == 0 && !c_flag && !s_flag) {
		shell = getenv("SHELL");
		if (shell != NULL && (len = strlen(shell)) > 2 &&
		    strncmp(shell + len - 3, "csh", 3) == 0)
			c_flag = 1;
	}
	if (k_flag) {
		const char *errstr = NULL;

		pidstr = getenv(SSH_AGENTPID_ENV_NAME);
		if (pidstr == NULL) {
			fprintf(stderr, "%s not set, cannot kill agent\n",
			    SSH_AGENTPID_ENV_NAME);
			exit(1);
		}
		pid = (int)strtonum(pidstr, 2, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr,
			    "%s=\"%s\", which is not a good PID: %s\n",
			    SSH_AGENTPID_ENV_NAME, pidstr, errstr);
			exit(1);
		}
		if (kill(pid, SIGTERM) == -1) {
			perror("kill");
			exit(1);
		}
		format = c_flag ? "unsetenv %s;\n" : "unset %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME);
		printf(format, SSH_AGENTPID_ENV_NAME);
		printf("echo Agent pid %ld killed;\n", (long)pid);
		exit(0);
	}

	/*
	 * Minimum file descriptors:
	 * stdio (3) + listener (1) + syslog (1 maybe) + connection (1) +
	 * a few spare for libc / stack protectors / sanitisers, etc.
	 */
#define SSH_AGENT_MIN_FDS (3+1+1+1+4)
	if (rlim.rlim_cur < SSH_AGENT_MIN_FDS)
		fatal("%s: file descriptor rlimit %lld too low (minimum %u)",
		    __progname, (long long)rlim.rlim_cur, SSH_AGENT_MIN_FDS);
	maxfds = rlim.rlim_cur - SSH_AGENT_MIN_FDS;

	parent_pid = getpid();

	if (agentsocket == NULL) {
		/* Create private directory for agent socket */
		mktemp_proto(socket_dir, sizeof(socket_dir));
		if (mkdtemp(socket_dir) == NULL) {
			perror("mkdtemp: private socket dir");
			exit(1);
		}
		snprintf(socket_name, sizeof socket_name, "%s/agent.%ld", socket_dir,
		    (long)parent_pid);
	} else {
		/* Try to use specified agent socket */
		socket_dir[0] = '\0';
		strlcpy(socket_name, agentsocket, sizeof socket_name);
	}

	/*
	 * Create socket early so it will exist before command gets run from
	 * the parent.
	 */
	prev_mask = umask(0177);
	sock = unix_listener(socket_name, SSH_LISTEN_BACKLOG, 0);
	if (sock < 0) {
		/* XXX - unix_listener() calls error() not perror() */
		*socket_name = '\0'; /* Don't unlink any existing file */
		cleanup_exit(1);
	}
	umask(prev_mask);

	/*
	 * Fork, and have the parent execute the command, if any, or present
	 * the socket data.  The child continues as the authentication agent.
	 */
	if (D_flag || d_flag) {
		log_init(__progname,
		    d_flag ? SYSLOG_LEVEL_DEBUG3 : SYSLOG_LEVEL_INFO,
		    SYSLOG_FACILITY_AUTH, 1);
		format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
		printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
		    SSH_AUTHSOCKET_ENV_NAME);
		printf("echo Agent pid %ld;\n", (long)parent_pid);
		fflush(stdout);
		goto skip;
	}
	pid = fork();
	if (pid == -1) {
		perror("fork");
		cleanup_exit(1);
	}
	if (pid != 0) {		/* Parent - execute the given command. */
		close(sock);
		snprintf(pidstrbuf, sizeof pidstrbuf, "%ld", (long)pid);
		if (ac == 0) {
			format = c_flag ? "setenv %s %s;\n" : "%s=%s; export %s;\n";
			printf(format, SSH_AUTHSOCKET_ENV_NAME, socket_name,
			    SSH_AUTHSOCKET_ENV_NAME);
			printf(format, SSH_AGENTPID_ENV_NAME, pidstrbuf,
			    SSH_AGENTPID_ENV_NAME);
			printf("echo Agent pid %ld;\n", (long)pid);
			exit(0);
		}
		if (setenv(SSH_AUTHSOCKET_ENV_NAME, socket_name, 1) == -1 ||
		    setenv(SSH_AGENTPID_ENV_NAME, pidstrbuf, 1) == -1) {
			perror("setenv");
			exit(1);
		}
		execvp(av[0], av);
		perror(av[0]);
		exit(1);
	}
	/* child */
	log_init(__progname, SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 0);

	if (setsid() == -1) {
		error("setsid: %s", strerror(errno));
		cleanup_exit(1);
	}

	(void)chdir("/");
	if (stdfd_devnull(1, 1, 1) == -1)
		error_f("stdfd_devnull failed");

#ifdef HAVE_SETRLIMIT
	/* deny core dumps, since memory contains unencrypted private keys */
	rlim.rlim_cur = rlim.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
		error("setrlimit RLIMIT_CORE: %s", strerror(errno));
		cleanup_exit(1);
	}
#endif

skip:

	cleanup_pid = getpid();

#ifdef ENABLE_PKCS11
	pkcs11_init(0);
#endif
	new_socket(AUTH_SOCKET, sock);
	if (ac > 0)
		parent_alive_interval = 10;
	idtab_init();
	ssh_signal(SIGPIPE, SIG_IGN);
	ssh_signal(SIGINT, (d_flag | D_flag) ? cleanup_handler : SIG_IGN);
	ssh_signal(SIGHUP, cleanup_handler);
	ssh_signal(SIGTERM, cleanup_handler);

	sigemptyset(&nsigset);
	sigaddset(&nsigset, SIGINT);
	sigaddset(&nsigset, SIGHUP);
	sigaddset(&nsigset, SIGTERM);

	if (pledge("stdio rpath cpath unix id proc exec", NULL) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	while (1) {
		sigprocmask(SIG_BLOCK, &nsigset, &osigset);
		if (signalled != 0) {
			logit("exiting on signal %d", (int)signalled);
			cleanup_exit(2);
		}
		ptimeout_init(&timeout);
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = ppoll(pfd, npfd, ptimeout_get_tsp(&timeout), &osigset);
		sigprocmask(SIG_SETMASK, &osigset, NULL);
		saved_errno = errno;
		if (parent_alive_interval != 0)
			check_parent_exists();
		(void) reaper();	/* remove expired keys */
		if (result == -1) {
			if (saved_errno == EINTR)
				continue;
			fatal("poll: %s", strerror(saved_errno));
		} else if (result > 0)
			after_poll(pfd, npfd, maxfds);
	}
	/* NOTREACHED */
}
