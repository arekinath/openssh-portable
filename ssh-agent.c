/* $OpenBSD: ssh-agent.c,v 1.257 2020/03/06 18:28:27 markus Exp $ */
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
#include <sys/param.h>
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
#include "sshbuf.h"
#include "sshkey.h"
#include "authfd.h"
#include "compat.h"
#include "log.h"
#include "misc.h"
#include "digest.h"
#include "ssherr.h"
#include "match.h"
#include "msg.h"
#include "ssherr.h"
#include "pathnames.h"
#include "ssh-pkcs11.h"
#include "sk-api.h"
#include "cipher.h"

#ifndef DEFAULT_PROVIDER_WHITELIST
# define DEFAULT_PROVIDER_WHITELIST "/usr/lib*/*,/usr/local/lib*/*"
#endif

/* Maximum accepted message length */
#define AGENT_MAX_LEN	(256*1024)
/* Maximum bytes to read from client socket */
#define AGENT_RBUF_LEN	(4096)

typedef enum {
	AUTH_UNUSED,
	AUTH_SOCKET,
	AUTH_CONNECTION
} sock_type;

typedef struct {
	int fd;
	sock_type type;
	struct sshbuf *input;
	struct sshbuf *output;
	struct sshbuf *request;
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

/* pid of process for which cleanup_socket is applicable */
pid_t cleanup_pid = 0;

/* pathname and directory for AUTH_SOCKET */
char socket_name[PATH_MAX];
char socket_dir[PATH_MAX];

/* PKCS#11/Security key path whitelist */
static char *provider_whitelist;

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
static long lifetime = 0;

static int fingerprint_hash = SSH_FP_HASH_DEFAULT;

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
	if ((rc = sshbuf_put_eckey8(buf, box->pdb_pub->ecdsa)) ||
	    (rc = sshbuf_put_eckey8(buf, box->pdb_ephem_pub->ecdsa)))
		return (rc);

	if ((rc = sshbuf_put_string8(buf, box->pdb_iv.b_data,
	    box->pdb_iv.b_len)))
		return (rc);

	if ((rc = sshbuf_put_string(buf, box->pdb_enc.b_data,
	    box->pdb_enc.b_len)))
		return (rc);

	return (0);
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
	struct sshkey *k = NULL;
	size_t len;
	uint8_t temp;
	char *tname = NULL;

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
	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = sshkey_curve_name_to_nid(tname);
	if (k->ecdsa_nid == -1) {
		rc = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	if (k->ecdsa == NULL)
		fatal("%s: new ec key for pub failed", __func__);

	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa))) {
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		goto out;
	}
	box->pdb_pub = k;
	k = NULL;

	k = sshkey_new(KEY_ECDSA);
	k->ecdsa_nid = box->pdb_pub->ecdsa_nid;

	k->ecdsa = EC_KEY_new_by_curve_name(k->ecdsa_nid);
	if (k->ecdsa == NULL)
		fatal("%s: new ec key for ephem pub failed", __func__);

	if ((rc = sshbuf_get_eckey8(buf, k->ecdsa))) {
		goto out;
	}
	if ((rc = sshkey_ec_validate_public(EC_KEY_get0_group(k->ecdsa),
	    EC_KEY_get0_public_key(k->ecdsa)))) {
		goto out;
	}
	box->pdb_ephem_pub = k;
	k = NULL;

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
	if (k != NULL)
		sshkey_free(k);
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

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(privkey->ecdsa));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	if (sec == NULL)
		fatal("%s: memory allocation failed", __func__);
	if ((rv = sshkey_unshield_private(privkey)) != 0) {
		verbose("%s: failed to unshield: %s", __func__, ssh_err(rv));
		return (rv);
	}
	rv = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(box->pdb_ephem_pub->ecdsa), privkey->ecdsa,
	    NULL);
	if (was_shielded)
		sshkey_shield_private(privkey);
	if (rv <= 0) {
		unsigned long ssl_err = ERR_peek_last_error();
		free(sec);
		error("%s: openssl error: %ld", __func__, ssl_err);
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

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(pkey->ecdsa));
	seclen = (fieldsz + 7) / 8;
	sec = calloc(1, seclen);
	if (sec == NULL)
		fatal("%s: memory alloc failed", __func__);
	rv = ECDH_compute_key(sec, seclen,
	    EC_KEY_get0_public_key(pubk->ecdsa), pkey->ecdsa, NULL);
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
	close(e->fd);
	e->fd = -1;
	e->type = AUTH_UNUSED;
	sshbuf_free(e->input);
	sshbuf_free(e->output);
	sshbuf_free(e->request);
}

static void
idtab_init(void)
{
	idtab = xcalloc(1, sizeof(*idtab));
	TAILQ_INIT(&idtab->idlist);
	idtab->nentries = 0;
}

static void
free_identity(Identity *id)
{
	sshkey_free(id->key);
	free(id->provider);
	free(id->comment);
	free(id->sk_provider);
	free(id);
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
confirm_key(Identity *id)
{
	char *p;
	int ret = -1;

	p = sshkey_fingerprint(id->key, fingerprint_hash, SSH_FP_DEFAULT);
	if (p != NULL &&
	    ask_permission("Allow use of key %s?\nKey fingerprint %s.",
	    id->comment, p))
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
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

/* send list of supported public keys to 'client' */
static void
process_request_identities(SocketEntry *e)
{
	Identity *id;
	struct sshbuf *msg;
	int r;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, idtab->nentries)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	TAILQ_FOREACH(id, &idtab->idlist, next) {
		if ((r = sshkey_puts_opts(id->key, msg, SSHKEY_SERIALIZE_INFO))
		     != 0 ||
		    (r = sshbuf_put_cstring(msg, id->comment)) != 0) {
			error("%s: put key/comment: %s", __func__,
			    ssh_err(r));
			continue;
		}
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
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

/* ssh2 only */
static void
process_sign_request2(SocketEntry *e)
{
	const u_char *data;
	u_char *signature = NULL;
	size_t dlen, slen = 0;
	u_int compat = 0, flags;
	int r, ok = -1;
	char *fp = NULL;
	struct sshbuf *msg;
	struct sshkey *key = NULL;
	struct identity *id;
	struct notifier_ctx *notifier = NULL;

	if ((msg = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshkey_froms(e->request, &key)) != 0 ||
	    (r = sshbuf_get_string_direct(e->request, &data, &dlen)) != 0 ||
	    (r = sshbuf_get_u32(e->request, &flags)) != 0) {
		error("%s: couldn't parse request: %s", __func__, ssh_err(r));
		goto send;
	}

	if ((id = lookup_identity(key)) == NULL) {
		verbose("%s: %s key not found", __func__, sshkey_type(key));
		goto send;
	}
	if (id->confirm && confirm_key(id) != 0) {
		verbose("%s: user refused key", __func__);
		goto send;
	}
	if (sshkey_is_sk(id->key) &&
	    (id->key->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		if ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL)
			fatal("%s: fingerprint failed", __func__);
		notifier = notify_start(0,
		    "Confirm user presence for key %s %s",
		    sshkey_type(id->key), fp);
	}
	if ((r = sshkey_sign(id->key, &signature, &slen,
	    data, dlen, agent_decode_alg(key, flags),
	    id->sk_provider, compat)) != 0) {
		error("%s: sshkey_sign: %s", __func__, ssh_err(r));
		goto send;
	}
	/* Success */
	ok = 0;
 send:
	notify_complete(notifier);
	sshkey_free(key);
	free(fp);
	if (ok == 0) {
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_SIGN_RESPONSE)) != 0 ||
		    (r = sshbuf_put_string(msg, signature, slen)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	} else if ((r = sshbuf_put_u8(msg, SSH_AGENT_FAILURE)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
	free(signature);
}

/* shared */
static void
process_remove_identity(SocketEntry *e)
{
	int r, success = 0;
	struct sshkey *key = NULL;
	Identity *id;

	if ((r = sshkey_froms(e->request, &key)) != 0) {
		error("%s: get key: %s", __func__, ssh_err(r));
		goto done;
	}
	if ((id = lookup_identity(key)) == NULL) {
		debug("%s: key not found", __func__);
		goto done;
	}
	/* We have this key, free it. */
	if (idtab->nentries < 1)
		fatal("%s: internal error: nentries %d",
		    __func__, idtab->nentries);
	TAILQ_REMOVE(&idtab->idlist, id, next);
	free_identity(id);
	idtab->nentries--;
	sshkey_free(key);
	success = 1;
 done:
	send_status(e, success);
}

static void
process_remove_all_identities(SocketEntry *e)
{
	Identity *id;

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

static void
process_add_identity(SocketEntry *e)
{
	Identity *id;
	int success = 0, confirm = 0;
	u_int seconds = 0, maxsign;
	char *fp, *comment = NULL, *ext_name = NULL, *sk_provider = NULL;
	char canonical_provider[PATH_MAX];
	time_t death = 0;
	struct sshkey *k = NULL;
	u_char ctype;
	int r = SSH_ERR_INTERNAL_ERROR;

	if ((r = sshkey_private_deserialize(e->request, &k)) != 0 ||
	    k == NULL ||
	    (r = sshbuf_get_cstring(e->request, &comment, NULL)) != 0) {
		error("%s: decode private key: %s", __func__, ssh_err(r));
		goto err;
	}
	while (sshbuf_len(e->request)) {
		if ((r = sshbuf_get_u8(e->request, &ctype)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto err;
		}
		switch (ctype) {
		case SSH_AGENT_CONSTRAIN_LIFETIME:
			if ((r = sshbuf_get_u32(e->request, &seconds)) != 0) {
				error("%s: bad lifetime constraint: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			death = monotime() + seconds;
			break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			confirm = 1;
			break;
		case SSH_AGENT_CONSTRAIN_MAXSIGN:
			if ((r = sshbuf_get_u32(e->request, &maxsign)) != 0) {
				error("%s: bad maxsign constraint: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			if ((r = sshkey_enable_maxsign(k, maxsign)) != 0) {
				error("%s: cannot enable maxsign: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			break;
		case SSH_AGENT_CONSTRAIN_EXTENSION:
			if ((r = sshbuf_get_cstring(e->request,
			    &ext_name, NULL)) != 0) {
				error("%s: cannot parse extension: %s",
				    __func__, ssh_err(r));
				goto err;
			}
			debug("%s: constraint ext %s", __func__, ext_name);
			if (strcmp(ext_name, "sk-provider@openssh.com") == 0) {
				if (sk_provider != NULL) {
					error("%s already set", ext_name);
					goto err;
				}
				if ((r = sshbuf_get_cstring(e->request,
				    &sk_provider, NULL)) != 0) {
					error("%s: cannot parse %s: %s",
					    __func__, ext_name, ssh_err(r));
					goto err;
				}
			} else {
				error("%s: unsupported constraint \"%s\"",
				    __func__, ext_name);
				goto err;
			}
			free(ext_name);
			break;
		default:
			error("%s: Unknown constraint %d", __func__, ctype);
 err:
			free(sk_provider);
			free(ext_name);
			sshbuf_reset(e->request);
			free(comment);
			sshkey_free(k);
			goto send;
		}
	}
	if (sk_provider != NULL) {
		if (!sshkey_is_sk(k)) {
			error("Cannot add provider: %s is not an "
			    "authenticator-hosted key", sshkey_type(k));
			free(sk_provider);
			goto send;
		}
		if (strcasecmp(sk_provider, "internal") == 0) {
			debug("%s: internal provider", __func__);
		} else {
			if (realpath(sk_provider, canonical_provider) == NULL) {
				verbose("failed provider \"%.100s\": "
				    "realpath: %s", sk_provider,
				    strerror(errno));
				free(sk_provider);
				goto send;
			}
			free(sk_provider);
			sk_provider = xstrdup(canonical_provider);
			if (match_pattern_list(sk_provider,
			    provider_whitelist, 0) != 1) {
				error("Refusing add key: "
				    "provider %s not whitelisted", sk_provider);
				free(sk_provider);
				goto send;
			}
		}
	}
	if ((r = sshkey_shield_private(k)) != 0) {
		error("%s: shield private key: %s", __func__, ssh_err(r));
		goto err;
	}

	success = 1;
	if (lifetime && !death)
		death = monotime() + lifetime;
	if ((id = lookup_identity(k)) == NULL) {
		id = xcalloc(1, sizeof(Identity));
		TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
		/* Increment the number of identities. */
		idtab->nentries++;
	} else {
		/* key state might have been updated */
		sshkey_free(id->key);
		free(id->comment);
		free(id->sk_provider);
	}
	id->key = k;
	id->comment = comment;
	id->death = death;
	id->confirm = confirm;
	id->sk_provider = sk_provider;

	if ((fp = sshkey_fingerprint(k, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == NULL)
		fatal("%s: sshkey_fingerprint failed", __func__);
	debug("%s: add %s %s \"%.100s\" (life: %u) (confirm: %u) "
	    "(provider: %s)", __func__, sshkey_ssh_name(k), fp, comment,
	    seconds, confirm, sk_provider == NULL ? "none" : sk_provider);
	free(fp);
send:
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

	/*
	 * This is deliberately fatal: the user has requested that we lock,
	 * but we can't parse their request properly. The only safe thing to
	 * do is abort.
	 */
	if ((r = sshbuf_get_cstring(e->request, &passwd, &pwlen)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
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
		fatal("%s: sshbuf_new failed", __func__);
	if ((r = sshbuf_put_u8(msg, SSH2_AGENT_IDENTITIES_ANSWER)) != 0 ||
	    (r = sshbuf_put_u32(msg, 0)) != 0 ||
	    (r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	sshbuf_free(msg);
}

#ifdef ENABLE_PKCS11
static void
process_add_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	char **comments = NULL;
	int r, i, count = 0, success = 0, confirm = 0;
	u_int seconds;
	time_t death = 0;
	u_char type;
	struct sshkey **keys = NULL, *k;
	Identity *id;

	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto send;
	}

	while (sshbuf_len(e->request)) {
		if ((r = sshbuf_get_u8(e->request, &type)) != 0) {
			error("%s: buffer error: %s", __func__, ssh_err(r));
			goto send;
		}
		switch (type) {
		case SSH_AGENT_CONSTRAIN_LIFETIME:
			if ((r = sshbuf_get_u32(e->request, &seconds)) != 0) {
				error("%s: buffer error: %s",
				    __func__, ssh_err(r));
				goto send;
			}
			death = monotime() + seconds;
			break;
		case SSH_AGENT_CONSTRAIN_CONFIRM:
			confirm = 1;
			break;
		default:
			error("%s: Unknown constraint type %d", __func__, type);
			goto send;
		}
	}
	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}
	if (match_pattern_list(canonical_provider, provider_whitelist, 0) != 1) {
		verbose("refusing PKCS#11 add of \"%.100s\": "
		    "provider not whitelisted", canonical_provider);
		goto send;
	}
	debug("%s: add %.100s", __func__, canonical_provider);
	if (lifetime && !death)
		death = monotime() + lifetime;

	count = pkcs11_add_provider(canonical_provider, pin, &keys, &comments);
	for (i = 0; i < count; i++) {
		k = keys[i];
		if (lookup_identity(k) == NULL) {
			id = xcalloc(1, sizeof(Identity));
			id->key = k;
			keys[i] = NULL; /* transferred */
			id->provider = xstrdup(canonical_provider);
			if (*comments[i] != '\0') {
				id->comment = comments[i];
				comments[i] = NULL; /* transferred */
			} else {
				id->comment = xstrdup(canonical_provider);
			}
			id->death = death;
			id->confirm = confirm;
			TAILQ_INSERT_TAIL(&idtab->idlist, id, next);
			idtab->nentries++;
			success = 1;
		}
		sshkey_free(keys[i]);
		free(comments[i]);
	}
send:
	free(pin);
	free(provider);
	free(keys);
	free(comments);
	send_status(e, success);
}

static void
process_remove_smartcard_key(SocketEntry *e)
{
	char *provider = NULL, *pin = NULL, canonical_provider[PATH_MAX];
	int r, success = 0;
	Identity *id, *nxt;

	if ((r = sshbuf_get_cstring(e->request, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(e->request, &pin, NULL)) != 0) {
		error("%s: buffer error: %s", __func__, ssh_err(r));
		goto send;
	}
	free(pin);

	if (realpath(provider, canonical_provider) == NULL) {
		verbose("failed PKCS#11 add of \"%.100s\": realpath: %s",
		    provider, strerror(errno));
		goto send;
	}

	debug("%s: remove %.100s", __func__, canonical_provider);
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
		error("%s: pkcs11_del_provider failed", __func__);
send:
	free(provider);
	send_status(e, success);
}
#endif /* ENABLE_PKCS11 */

struct exthandler {
	const char *eh_name;
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
	if (id->confirm && confirm_key(id) != 0) {
		verbose("%s: user refused key", __func__);
		goto send;
	}
	if (sshkey_is_sk(id->key)) {
		verbose("%s: not supported for sk keys", __func__);
		goto send;
	}
	if (id->key->type != KEY_ECDSA || id->key->ecdsa == NULL) {
		verbose("%s: not an ecdsa key", __func__);
		goto send;
	}
	if (id->key->ecdsa_nid != partner->ecdsa_nid) {
		verbose("%s: curve mismatch", __func__);
		goto send;
	}

	fieldsz = EC_GROUP_get_degree(EC_KEY_get0_group(id->key->ecdsa));
	seclen = (fieldsz + 7) / 8;
	secret = calloc(1, seclen);
	if (secret == NULL)
		fatal("%s: failed to allocate memory", __func__);
	was_shielded = sshkey_is_shielded(id->key);
	if ((r = sshkey_unshield_private(id->key)) != 0) {
		verbose("%s: failed to unshield: %s", __func__, ssh_err(r));
		goto send;
	}
	r = ECDH_compute_key(secret, seclen,
	    EC_KEY_get0_public_key(partner->ecdsa), id->key->ecdsa, NULL);
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
	} else if ((r = sshbuf_put_u8(msg, SSH2_AGENT_EXT_FAILURE)) != 0)
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
	if (id->confirm && confirm_key(id) != 0) {
		verbose("%s: user refused key", __func__);
		goto send;
	}
	if (sshkey_is_sk(id->key)) {
		verbose("%s: not supported for sk keys", __func__);
		goto send;
	}
	if (id->key->type != KEY_ECDSA || id->key->ecdsa == NULL) {
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
		if ((r = sshbuf_put_u8(msg, SSH2_AGENT_EXT_FAILURE)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	if ((r = sshbuf_put_stringb(e->output, msg)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	sshbuf_free(msg);
}

struct exthandler exthandlers[] = {
	{ "query", process_ext_query },
	{ "ecdh@joyent.com", process_ext_ecdh },
	{ "ecdh-rebox@joyent.com", process_ext_ecdh_rebox },
	{ NULL, NULL }
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

	if ((r = sshbuf_froms(e->request, &inner))) {
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

	hdlr->eh_handler(e, inner);
	goto out;
err:
	sshbuf_reset(e->request);
	send_status(e, 0);
out:
	sshbuf_free(inner);
	free(extname);
}

/* dispatch incoming messages */

static int
process_message(u_int socknum)
{
	u_int msg_len;
	u_char type;
	const u_char *cp;
	int r;
	SocketEntry *e;

	if (socknum >= sockets_alloc) {
		fatal("%s: socket number %u >= allocated %u",
		    __func__, socknum, sockets_alloc);
	}
	e = &sockets[socknum];

	if (sshbuf_len(e->input) < 5)
		return 0;		/* Incomplete message header. */
	cp = sshbuf_ptr(e->input);
	msg_len = PEEK_U32(cp);
	if (msg_len > AGENT_MAX_LEN) {
		debug("%s: socket %u (fd=%d) message too long %u > %u",
		    __func__, socknum, e->fd, msg_len, AGENT_MAX_LEN);
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
			debug("%s: buffer error: %s", __func__, ssh_err(r));
			return -1;
		}
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}

	debug("%s: socket %u (fd=%d) type %d", __func__, socknum, e->fd, type);

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
		return 0;
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
	case SSH2_AGENTC_EXTENSION:
		process_extension(e);
		break;
	default:
		/* Unknown message.  Respond with failure. */
		error("Unknown message %d", type);
		sshbuf_reset(e->request);
		send_status(e, 0);
		break;
	}
	return 0;
}

static void
new_socket(sock_type type, int fd)
{
	u_int i, old_alloc, new_alloc;

	set_nonblock(fd);

	if (fd > max_fd)
		max_fd = fd;

	for (i = 0; i < sockets_alloc; i++)
		if (sockets[i].type == AUTH_UNUSED) {
			sockets[i].fd = fd;
			if ((sockets[i].input = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].output = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			if ((sockets[i].request = sshbuf_new()) == NULL)
				fatal("%s: sshbuf_new failed", __func__);
			sockets[i].type = type;
			return;
		}
	old_alloc = sockets_alloc;
	new_alloc = sockets_alloc + 10;
	sockets = xreallocarray(sockets, new_alloc, sizeof(sockets[0]));
	for (i = old_alloc; i < new_alloc; i++)
		sockets[i].type = AUTH_UNUSED;
	sockets_alloc = new_alloc;
	sockets[old_alloc].fd = fd;
	if ((sockets[old_alloc].input = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].output = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((sockets[old_alloc].request = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
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
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_put(sockets[socknum].input, buf, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	explicit_bzero(buf, sizeof(buf));
	process_message(socknum);
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
			error("%s: read error on socket %u (fd %d): %s",
			    __func__, socknum, sockets[socknum].fd,
			    strerror(errno));
		}
		return -1;
	}
	if ((r = sshbuf_consume(sockets[socknum].output, len)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
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
			error("%s: no socket for fd %d", __func__, pfd[i].fd);
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
			if ((pfd[i].revents & (POLLIN|POLLERR)) != 0 &&
			    handle_conn_read(socknum) != 0) {
				goto close_sock;
			}
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
prepare_poll(struct pollfd **pfdp, size_t *npfdp, int *timeoutp, u_int maxfds)
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
		fatal("%s: recallocarray failed", __func__);
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
			else if (r != SSH_ERR_NO_BUFFER_SPACE) {
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			}
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
	if (deadline == 0) {
		*timeoutp = -1; /* INFTIM */
	} else {
		if (deadline > INT_MAX / 1000)
			*timeoutp = INT_MAX / 1000;
		else
			*timeoutp = deadline * 1000;
	}
	return (1);
}

static void
cleanup_socket(void)
{
	if (cleanup_pid != 0 && getpid() != cleanup_pid)
		return;
	debug("%s: cleanup", __func__);
	if (socket_name[0])
		unlink(socket_name);
	if (socket_dir[0])
		rmdir(socket_dir);
}

void
cleanup_exit(int i)
{
	cleanup_socket();
	_exit(i);
}

/*ARGSUSED*/
static void
cleanup_handler(int sig)
{
	cleanup_socket();
#ifdef ENABLE_PKCS11
	pkcs11_terminate();
#endif
	_exit(2);
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
	    "                 [-P provider_whitelist] [-t life] [command [arg ...]]\n"
	    "       ssh-agent [-c | -s] -k\n");
	exit(1);
}

int
main(int ac, char **av)
{
	int c_flag = 0, d_flag = 0, D_flag = 0, k_flag = 0, s_flag = 0;
	int sock, fd, ch, result, saved_errno;
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
	int timeout = -1; /* INFTIM */
	struct pollfd *pfd = NULL;
	size_t npfd = 0;
	u_int maxfds;

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	sanitise_stdfd();

	/* drop */
	setegid(getgid());
	setgid(getgid());

	platform_disable_tracing(0);	/* strict=no */

#ifdef RLIMIT_NOFILE
	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1)
		fatal("%s: getrlimit: %s", __progname, strerror(errno));
#endif

	__progname = ssh_get_progname(av[0]);
	seed_rng();

	while ((ch = getopt(ac, av, "cDdksE:a:P:t:U")) != -1) {
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
		case 'P':
			if (provider_whitelist != NULL)
				fatal("-P option already specified");
			provider_whitelist = xstrdup(optarg);
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

	if (provider_whitelist == NULL)
		provider_whitelist = xstrdup(DEFAULT_PROVIDER_WHITELIST);

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
	if ((fd = open(_PATH_DEVNULL, O_RDWR, 0)) != -1) {
		/* XXX might close listen socket */
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			close(fd);
	}

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

	if (pledge("stdio rpath cpath unix id proc exec", NULL) == -1)
		fatal("%s: pledge: %s", __progname, strerror(errno));
	platform_pledge_agent();

	while (1) {
		prepare_poll(&pfd, &npfd, &timeout, maxfds);
		result = poll(pfd, npfd, timeout);
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
