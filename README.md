Uses the following EST implementation: https://github.com/globalsign/est

est-client-getca EXAMPLE NOT WORKING:

github.com/globalsign/tpmkeys
/go/pkg/mod/github.com/globalsign/tpmkeys@v1.0.1/key.go:68:23: not enough arguments in call to tpm2.Sign
        have (io.ReadWriter, tpmutil.Handle, string, []byte, *tpm2.SigScheme)
        want (io.ReadWriter, tpmutil.Handle, string, []byte, *tpm2.Ticket, *tpm2.SigScheme)