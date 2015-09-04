/* $OpenBSD: compat.c,v 1.113 2018/08/13 02:41:05 djm Exp $ */
/*
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "xmalloc.h"
#include "packet.h"
#include "compat.h"
#include "log.h"
#include "match.h"
#include "kex.h"

int datafellows = 0;

/* datafellows bug compatibility */
u_int
compat_datafellows(const char *version)
{
	int i;
	static struct {
		char	*pat;
		int	bugs;
	} check[] = {
		{ "OpenSSH_2.*,"
		  "OpenSSH_3.0*,"
		  "OpenSSH_3.1*",	SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_3.*",	SSH_OLD_FORWARD_ADDR|SSH_BUG_SIGTYPE },
		{ "Sun_SSH_1.0*",	SSH_BUG_NOREKEY|SSH_BUG_EXTEOF|
					SSH_BUG_SIGTYPE|SSH_OLD_DHGEX},
		{ "Sun_SSH_1.5*",	SSH_BUG_SIGTYPE|SSH_OLD_DHGEX},
		{ "OpenSSH_2*,"
		  "OpenSSH_3*,"
		  "OpenSSH_4*",		SSH_BUG_SIGTYPE },
		{ "OpenSSH_5*",		SSH_NEW_OPENSSH|SSH_BUG_DYNAMIC_RPORT|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_6.6.1*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE},
		{ "OpenSSH_6.5*,"
		  "OpenSSH_6.6*",	SSH_NEW_OPENSSH|SSH_BUG_CURVE25519PAD|
					SSH_BUG_SIGTYPE},
		{ "OpenSSH_7.0*,"
		  "OpenSSH_7.1*,"
		  "OpenSSH_7.2*,"
		  "OpenSSH_7.3*,"
		  "OpenSSH_7.4*,"
		  "OpenSSH_7.5*,"
		  "OpenSSH_7.6*,"
		  "OpenSSH_7.7*",	SSH_NEW_OPENSSH|SSH_BUG_SIGTYPE},
		{ "OpenSSH*",		SSH_NEW_OPENSSH },
		{ "*MindTerm*",		0 },
		{ "3.0.*",		SSH_BUG_DEBUG },
		{ "3.0 SecureCRT*",	SSH_OLD_SESSIONID },
		{ "1.7 SecureFX*",	SSH_OLD_SESSIONID },
		{ "1.2.18*,"
		  "1.2.19*,"
		  "1.2.20*,"
		  "1.2.21*,"
		  "1.2.22*",		SSH_BUG_IGNOREMSG },
		{ "1.3.2*",		/* F-Secure */
					SSH_BUG_IGNOREMSG },
		{ "Cisco-1.*",		SSH_BUG_DHGEX_LARGE|
					SSH_BUG_HOSTKEYS },
		{ "*SSH Compatible Server*",			/* Netscreen */
					SSH_BUG_PASSWORDPAD },
		{ "*OSU_0*,"
		  "OSU_1.0*,"
		  "OSU_1.1*,"
		  "OSU_1.2*,"
		  "OSU_1.3*,"
		  "OSU_1.4*,"
		  "OSU_1.5alpha1*,"
		  "OSU_1.5alpha2*,"
		  "OSU_1.5alpha3*",	SSH_BUG_PASSWORDPAD },
		{ "*SSH_Version_Mapper*",
					SSH_BUG_SCANNER },
		{ "PuTTY_Local:*,"	/* dev versions < Sep 2014 */
		  "PuTTY-Release-0.5*," /* 0.50-0.57, DH-GEX in >=0.52 */
		  "PuTTY_Release_0.5*,"	/* 0.58-0.59 */
		  "PuTTY_Release_0.60*,"
		  "PuTTY_Release_0.61*,"
		  "PuTTY_Release_0.62*,"
		  "PuTTY_Release_0.63*,"
		  "PuTTY_Release_0.64*",
					SSH_OLD_DHGEX },
		{ "FuTTY*",		SSH_OLD_DHGEX }, /* Putty Fork */
		{ "Probe-*",
					SSH_BUG_PROBE },
		{ "TeraTerm SSH*,"
		  "TTSSH/1.5.*,"
		  "TTSSH/2.1*,"
		  "TTSSH/2.2*,"
		  "TTSSH/2.3*,"
		  "TTSSH/2.4*,"
		  "TTSSH/2.5*,"
		  "TTSSH/2.6*,"
		  "TTSSH/2.70*,"
		  "TTSSH/2.71*,"
		  "TTSSH/2.72*",	SSH_BUG_HOSTKEYS },
		{ "WinSCP_release_4*,"
		  "WinSCP_release_5.0*,"
		  "WinSCP_release_5.1,"
		  "WinSCP_release_5.1.*,"
		  "WinSCP_release_5.5,"
		  "WinSCP_release_5.5.*,"
		  "WinSCP_release_5.6,"
		  "WinSCP_release_5.6.*,"
		  "WinSCP_release_5.7,"
		  "WinSCP_release_5.7.1,"
		  "WinSCP_release_5.7.2,"
		  "WinSCP_release_5.7.3,"
		  "WinSCP_release_5.7.4",
					SSH_OLD_DHGEX },
		{ "ConfD-*",
					SSH_BUG_UTF8TTYMODE },
		{ "Twisted_*",		0 },
		{ "Twisted*",		SSH_BUG_DEBUG },
		{ NULL,			0 }
	};

	/* process table, return first match */
	for (i = 0; check[i].pat; i++) {
		if (match_pattern_list(version, check[i].pat, 0) == 1) {
			debug("match: %s pat %s compat 0x%08x",
			    version, check[i].pat, check[i].bugs);
			datafellows = check[i].bugs;	/* XXX for now */
			return check[i].bugs;
		}
	}
	debug("no match: %s", version);
	return 0;
}

#define	SEP	","
int
proto_spec(const char *spec)
{
	char *s, *p, *q;
	int ret = SSH_PROTO_UNKNOWN;

	if (spec == NULL)
		return ret;
	q = s = strdup(spec);
	if (s == NULL)
		return ret;
	for ((p = strsep(&q, SEP)); p && *p != '\0'; (p = strsep(&q, SEP))) {
		switch (atoi(p)) {
		case 2:
			ret |= SSH_PROTO_2;
			break;
		default:
			logit("ignoring bad proto spec: '%s'.", p);
			break;
		}
	}
	free(s);
	return ret;
}

/*
 * Filters a proposal string, excluding any algorithm matching the 'filter'
 * pattern list.
 */
static char *
filter_proposal(char *proposal, const char *filter)
{
	struct sshbuf *b;
	int rc;
	char *orig_prop, *fix_prop;
	char *cp, *tmp;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	tmp = orig_prop = xstrdup(proposal);
	while ((cp = strsep(&tmp, ",")) != NULL) {
		if (match_pattern_list(cp, filter, 0) != 1) {
			if (sshbuf_len(b) > 0) {
				if ((rc = sshbuf_put_u8(b, ','))) {
					fatal("%s: sshbuf_put_u8 returned %d",
					    __func__, rc);
				}
			}
			if ((rc = sshbuf_put(b, cp, strlen(cp)))) {
				fatal("%s: sshbuf_put returned %d",
				    __func__, rc);
			}
		} else
			debug2("Compat: skipping algorithm \"%s\"", cp);
	}
	if ((rc = sshbuf_put_u8(b, 0)))
		fatal("%s: sshbuf_put_u8 returned %d", __func__, rc);
	fix_prop = xstrdup((char *)sshbuf_ptr(b));
	if (fix_prop == NULL)
		fatal("%s: xstrdup failed", __func__);
	sshbuf_free(b);
	free(orig_prop);

	return fix_prop;
}

/*
 * Adds an algorithm to the end of a proposal list, only if the algorithm is
 * not already present.
 */
static char *
append_proposal(char *proposal, const char *append)
{
	struct sshbuf *b;
	char *fix_prop;
	int rc;

	if (strstr(proposal, append) != NULL)
		return proposal;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);
	if ((rc = sshbuf_put(b, proposal, strlen(proposal))))
		fatal("%s: sshbuf_put returned %d", __func__, rc);
	if (sshbuf_len(b) > 0) {
		if ((rc = sshbuf_put_u8(b, ',')))
			fatal("%s: sshbuf_put_u8 returned %d", __func__, rc);
	}
	if ((rc = sshbuf_put(b, append, strlen(append))) ||
	    (rc = sshbuf_put_u8(b, 0)))
		fatal("%s: buffer error: %d", __func__, rc);
	fix_prop = xstrdup((char *)sshbuf_ptr(b));
	if (fix_prop == NULL)
		fatal("%s: xstrdup failed", __func__);
	sshbuf_free(b);

	return fix_prop;
}

char *
compat_cipher_proposal(char *cipher_prop)
{
	if (!(datafellows & SSH_BUG_BIGENDIANAES))
		return cipher_prop;
	debug2("%s: original cipher proposal: %s", __func__, cipher_prop);
	if ((cipher_prop = match_filter_blacklist(cipher_prop, "aes*")) == NULL)
		fatal("match_filter_blacklist failed");
	debug2("%s: compat cipher proposal: %s", __func__, cipher_prop);
	if (*cipher_prop == '\0')
		fatal("No supported ciphers found");
	return cipher_prop;
}

char *
compat_pkalg_proposal(char *pkalg_prop)
{
	if (!(datafellows & SSH_BUG_RSASIGMD5))
		return pkalg_prop;
	debug2("%s: original public key proposal: %s", __func__, pkalg_prop);
	if ((pkalg_prop = match_filter_blacklist(pkalg_prop, "ssh-rsa")) == NULL)
		fatal("match_filter_blacklist failed");
	debug2("%s: compat public key proposal: %s", __func__, pkalg_prop);
	if (*pkalg_prop == '\0')
		fatal("No supported PK algorithms found");
	return pkalg_prop;
}

char *
compat_kex_proposal(char *p)
{
	if ((datafellows & (SSH_BUG_CURVE25519PAD|SSH_OLD_DHGEX)) == 0)
		return p;
	debug2("%s: original KEX proposal: %s", __func__, p);
	if ((datafellows & SSH_BUG_CURVE25519PAD) != 0)
		if ((p = match_filter_blacklist(p,
		    "curve25519-sha256@libssh.org")) == NULL)
			fatal("match_filter_blacklist failed");
	if ((datafellows & SSH_OLD_DHGEX) != 0) {
		p = filter_proposal(p, "diffie-hellman-group-exchange-sha256");
		p = filter_proposal(p, "diffie-hellman-group-exchange-sha1");
		p = append_proposal(p, "diffie-hellman-group14-sha1");
		p = append_proposal(p, "diffie-hellman-group1-sha1");
	}
	debug2("%s: compat KEX proposal: %s", __func__, p);
	if (*p == '\0')
		fatal("No supported key exchange algorithms found");
	return p;
}

