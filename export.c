/*
 * export.c
 */

#include "pgpdump.h"

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
export_ssh2_key(const char *path)
{
	FILE		*f;
	uint32_t	len					= 0;
	uint32_t	SSHComMagicValue	= 0x3f6ff9eb;
	char		*RsaKeyIdentifier	= "if-modn{sign{rsa-pkcs1-sha1},encrypt{rsa-pkcs1v2-oaep}}";
	char		*NoCipher			= "none";

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

	if (!(f = fopen(path, "wb"))) {
		warning("can't open %s.", path);
		free_export_params();
		return;
	}

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

	fflush(f);
	fclose(f);

	free_export_params();
	return;
}

