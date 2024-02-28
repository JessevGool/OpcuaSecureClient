package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"

	"github.com/pkg/errors"
)

func main() {

	currentWD, err := os.Getwd()
	batPath := currentWD + "/MiloServer/milo-demo-server/milo-demo-server/bin/milo-demo-server.bat"

	if _, err := os.Stat(batPath); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Unzipping miloserver...\n")
		err := Unzip("./MiloServer/milo-demo-server-win.zip", "./MiloServer/milo-demo-server")
		if err != nil {
			println("Error while unzipping server")
		}
		fmt.Printf("Unzipping miloserver completed\n")
	}

	if _, err := os.Stat(batPath); errors.Is(err, os.ErrNotExist) {
		println(batPath + " not found, unzip manually")
	}
	//Can be used to start the server, but you can just run the .bat file
	//log.Println("Starting Server....")
	//err := StartServer()
	//if err != nil {
	//	fmt.Printf("Eror occured while starting server: %v", err)
	//	os.Exit(0)
	//}
	//log.Println("Server started")

	if err := ensurePKI(); err != nil {
		fmt.Println(errors.Wrap(err, "Error creating pki"))
		os.Exit(1)
	}
	// check if server is listening at endpointURL
	ctx := context.Background()
	ch, err := client.Dial(
		ctx,
		"opc.tcp://localhost:62541/milo",
		//client.WithUserNameIdentity("user1", "password"), // Username Password combination can be added
		client.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256, ua.MessageSecurityModeSignAndEncrypt), // Depending on what the server accepts this policy can be changed
		client.WithClientCertificatePaths("./pki/client.crt", "./pki/client.key"),                        // These will be auto generated at first launch, they will need to be put in the trusted folder of the Milo server
		client.WithInsecureSkipVerify(),
	)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	} else {
		println("Client connected")
	}

	// Prepare read request
	req := &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{
			{
				NodeID:      ua.VariableIDServerServerStatus,
				AttributeID: ua.AttributeIDValue,
			},
		},
	}

	// send request to server. receive response or error
	res, err := ch.Read(ctx, req)
	if err != nil {
		fmt.Printf("Error reading ServerStatus. %s\n", err.Error())
		ch.Abort(ctx)
		return
	}

	if serverStatus, ok := res.Results[0].Value.(ua.ServerStatusDataType); ok {
		fmt.Printf("Server status:\n")
		fmt.Printf("  ProductName: %s\n", serverStatus.BuildInfo.ProductName)
		fmt.Printf("  ManufacturerName: %s\n", serverStatus.BuildInfo.ManufacturerName)
		fmt.Printf("  State: %s\n", serverStatus.State)
	} else {
		fmt.Println("Error decoding ServerStatus.")
	}

	/**

	The output should be as follows if you are using the included MiloServer

	Server status:
	  ProductName: Eclipse Milo OPC UA Demo Server
	  ManufacturerName: digitalpetri
	  State: Running

	*/

	err = ch.Close(ctx)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		ch.Abort(ctx)
		return

	}

}

func StartServer() error {
	currentWD, err := os.Getwd()
	batPath := currentWD + "/MiloServer/milo-demo-server/milo-demo-server/bin/milo-demo-server.bat"

	if _, err := os.Stat(batPath); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Unzipping miloserver...\n")
		err := Unzip("./MiloServer/milo-demo-server-win.zip", "./MiloServer/milo-demo-server")
		if err != nil {
			return errors.New("Error while unzipping server")
		}
		fmt.Printf("Unzipping miloserver completed\n")
	}

	if _, err := os.Stat(batPath); errors.Is(err, os.ErrNotExist) {
		return errors.New(batPath + " not found, unzip manually")
	}

	// Get the directory of the .bat file
	batDir := filepath.Dir(batPath)

	// Change the working directory to the .bat file directory
	err = os.Chdir(batDir)
	if err != nil {
		return err
	}

	// Command to run the .bat file in a separate window
	cmd := exec.Command("cmd.exe", "/C", "start", batPath)

	// Run the command
	err = cmd.Start()
	if err != nil {
		// Handle error
		panic(err)
	}

	time.Sleep(8 * time.Second)
	return nil
}

func createNewCertificate(appName, certFile, keyFile string) error {

	// Create a keypair.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	// get local hostname.
	host, _ := os.Hostname()

	// get local ip address.
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ua.BadCertificateInvalid
	}
	conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// Create a certificate.
	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:%s", host, appName))
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	subjectKeyHash := sha1.New()
	subjectKeyHash.Write(key.PublicKey.N.Bytes())
	subjectKeyId := subjectKeyHash.Sum(nil)
	oidDC := asn1.ObjectIdentifier([]int{0, 9, 2342, 19200300, 100, 1, 25})

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: appName, ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: host}}},
		SubjectKeyId:          subjectKeyId,
		AuthorityKeyId:        subjectKeyId,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host, "localhost"},
		IPAddresses:           []net.IP{localAddr.IP, []byte{127, 0, 0, 1}},
		URIs:                  []*url.URL{applicationURI},
	}

	rawcrt, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return ua.BadCertificateInvalid
	}

	if f, err := os.Create(certFile); err == nil {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: rawcrt}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	if f, err := os.Create(keyFile); err == nil {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else {
		return err
	}

	return nil
}

func ensurePKI() error {

	// check if ./pki already exists
	if _, err := os.Stat("./pki"); !os.IsNotExist(err) {
		return nil
	}

	// make a pki directory, if not exist
	if err := os.MkdirAll("./pki", os.ModeDir|0755); err != nil {
		return err
	}

	// create a client cert in ./pki
	if err := createNewCertificate("test-client", "./pki/client.crt", "./pki/client.key"); err != nil {
		return err
	}

	// create a server cert in ./pki
	if err := createNewCertificate("testserver", "./pki/server.crt", "./pki/server.key"); err != nil {
		return err
	}
	return nil
}

func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		// Check for ZipSlip (Directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		err := extractAndWriteFile(f)
		if err != nil {
			return err
		}
	}

	return nil
}
