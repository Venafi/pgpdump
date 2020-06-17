/*
 * export.c
 */

#include "pgpdump.h"
#include <stdint.h>

public int
do_write(void *data, size_t len, FILE *f)
{
	int		r	= 0;
	byte	*d	= (byte *) data;

	while (len > 0) {
		len--;
		r += fwrite(&d[len], sizeof(byte), 1, f);
	}

	return r;
}

public int
validate_export_param(exportParam *param)
{
	if (!param || !param->data) {
		return 1;
	}

	if (0 == param->bytes || param->bytes != param->used) {
		return 1;
	}

	return 0;
}

public int
write_export_param(exportParam *param, FILE *f)
{
	int				r = 0;
	uint32_t		len;

	/* Each key parameter is prefixed with its size in bits, not bytes */
	if (!param || !param->data || !f) {
		return 0;
	}

	len = param->bits;
	r += do_write(&len, sizeof(len), f);

	r += fwrite(param->data, sizeof(byte), param->bytes, f);

	return r;
}

public void
free_export_param(exportParam *param)
{
	if (!param) {
		return;
	}

	if (param->data) {
		free(param->data);
		param->data = NULL;
	}

	memset(param, 0, sizeof(exportParam));
}

public void
free_export_params(void)
{
	free_export_param(&exportData.rsa.e);
	free_export_param(&exportData.rsa.d);
	free_export_param(&exportData.rsa.n);
	free_export_param(&exportData.rsa.u);
	free_export_param(&exportData.rsa.q);
	free_export_param(&exportData.rsa.p);
}

public void
export_ssh2_key(int id)
{
	FILE		*f;
	uint32_t	len					= 0;
	uint32_t	SSHComMagicValue	= 0x3f6ff9eb;
	char		*RsaKeyIdentifier	= "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}";
	char		*NoCipher			= "none";
	byte		*value				= NULL;
	char		*b64				= NULL;
	char		path[256];

	if (validate_export_param(&exportData.rsa.e) ||
		validate_export_param(&exportData.rsa.d) ||
		validate_export_param(&exportData.rsa.n) ||
		validate_export_param(&exportData.rsa.u) ||
		validate_export_param(&exportData.rsa.q) ||
		validate_export_param(&exportData.rsa.p)
	) {
		warning("unable to export private key; required parameters were not found.");
		free_export_params();
		return;
	}

	sprintf(path, "secret-key.%d", id);
	if (!(f = fopen(path, "wb+"))) {
		warning("can't open %s.", path);
		free_export_params();
		return;
	}
	exportID++;

	do_write(&SSHComMagicValue, sizeof(SSHComMagicValue), f);

	/*
		Write the total size of the file as 0 for now, and we will seek back
		to fix it at the end.
	*/
	do_write(&len, sizeof(len), f);

	/* We only support RSA keys currently */
	len = strlen(RsaKeyIdentifier);
	do_write(&len, sizeof(len), f);
	fwrite(RsaKeyIdentifier, sizeof(byte), len, f);

	/* We do not support encrypted keys currently */
	len = strlen(NoCipher);
	do_write(&len, sizeof(len), f);
	fwrite(NoCipher, sizeof(byte), len, f);

	/* The length of all the keydata, including its length */
	len = sizeof(len);
	len += exportData.rsa.e.bytes + sizeof(len);
	len += exportData.rsa.d.bytes + sizeof(len);
	len += exportData.rsa.n.bytes + sizeof(len);
	len += exportData.rsa.u.bytes + sizeof(len);
	len += exportData.rsa.q.bytes + sizeof(len);
	len += exportData.rsa.p.bytes + sizeof(len);
	do_write(&len, sizeof(len), f);

	/* The length of all the keydata, not including its length */
	len -= sizeof(len);
	do_write(&len, sizeof(len), f);

	/* The RSA key data parameters */
	write_export_param(&exportData.rsa.e, f);
	write_export_param(&exportData.rsa.d, f);
	write_export_param(&exportData.rsa.n, f);
	write_export_param(&exportData.rsa.u, f);
	write_export_param(&exportData.rsa.q, f);
	write_export_param(&exportData.rsa.p, f);

	/* Fix the size */
	len = ftell(f);
	fseek(f, sizeof(len), SEEK_SET);
	do_write(&len, sizeof(len), f);

	/* Complete */
	fflush(f);

	/* Re-read the entire key to prepare for wrapping in PEM format */
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (!(value = calloc(1, len + 1))) {
		warning("unable to PEM encode private key; allocation failure.");
	} else if (len != fread(value, 1, len, f)) {
		warning("unable to PEM encode private key; could not read exported key.");
	} else if (!(b64 = EncodeBase64(value, len))) {
		warning("unable to PEM encode private key; base64 encoding failedd.");
	} else {
		fseek(f, 0, SEEK_SET);

		fprintf(f, "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\n");
		fprintf(f, "Comment: Creation Date: ");
		write_time(key_creation_time, f);
		fprintf(f, "\n");

		fprintf(f, "%s\n", b64);
		fprintf(f, "---- END SSH2 ENCRYPTED PRIVATE KEY ----\n");
	}

	if (value) {
		free(value);
		value = NULL;
	}

	if (b64) {
		free(b64);
		b64 = NULL;
	}

	fclose(f);

	free_export_params();
	return;
}

const char *Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

public char *
EncodeBase64(const byte *UnencodedString, int length)
{
	int InLength;
	int OutLength;
	int Groups;
	int i;
	register unsigned char *ps_OutBuf;
	register unsigned char *ps_Out;
	register const unsigned char *ps_In;
	register int na, nb, nc;
	register unsigned char cha, chb, chc, chd;
	char *ptr;
	int LeftOver;

	if (!UnencodedString) {
		return(NULL);
	} else {
		if (length == 0) {
			InLength = (int)strlen((const char *)UnencodedString);
			if (InLength == 0) {
				return(NULL);
			}
		} else {
			InLength = length;
		}
	}

	OutLength = ((InLength + 2) / 3) * 4;
	Groups = InLength / 3;

	/* create a buffer for the encoded output */
	ps_OutBuf = malloc(OutLength);
	if (ps_OutBuf == NULL) {
		return NULL;
	}

	ps_Out = ps_OutBuf;
	ps_In = UnencodedString;

	for (i = 0; i<Groups; i++)
	{
		na = (unsigned char)(*ps_In++);
		nb = (unsigned char)(*ps_In++);
		nc = (unsigned char)(*ps_In++);

		cha = (unsigned char)(na >> 2);
		chb = (unsigned char)(((na << 4) + (nb >> 4)) & 63);
		chc = (unsigned char)(((nb << 2) + (nc >> 6)) & 63);
		chd = (unsigned char)(nc & 63);

		*ps_Out++ = Base64Chars[cha];
		*ps_Out++ = Base64Chars[chb];
		*ps_Out++ = Base64Chars[chc];
		*ps_Out++ = Base64Chars[chd];
	}
	LeftOver = InLength - Groups * 3;

	if (LeftOver == 1) {
		na = (unsigned char)(*ps_In++);
		*ps_Out++ = Base64Chars[na >> 2];
		*ps_Out++ = Base64Chars[(na & 3) << 4];
		*ps_Out++ = '=';
		*ps_Out++ = '=';
	}

	if (LeftOver == 2) {
		na = (unsigned char)(*ps_In++);
		nb = (unsigned char)(*ps_In++);
		*ps_Out++ = Base64Chars[na >> 2];
		*ps_Out++ = Base64Chars[((na & 3) << 4) + (nb >> 4)];
		*ps_Out++ = Base64Chars[((nb & 15) << 2)];
		*ps_Out++ = '=';
	}

	ptr = malloc((size_t)OutLength + 1);
	if (ptr != NULL) {
		memcpy(ptr, ps_OutBuf, OutLength);
		ptr[OutLength] = '\0';
	}
	free(ps_OutBuf);
	return(ptr);
}

