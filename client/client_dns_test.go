package client

import (
	"encoding/hex"
	"gitlab.akb-it.ru/cloud_sber/gokrb5/config"
	"gitlab.akb-it.ru/cloud_sber/gokrb5/keytab"
	"gitlab.akb-it.ru/cloud_sber/gokrb5/test"
	"gitlab.akb-it.ru/cloud_sber/gokrb5/test/testdata"
	"testing"
)

func TestClient_Login_DNSKDCs(t *testing.T) {
	test.Privileged(t)

	//ns := os.Getenv("DNSUTILS_OVERRIDE_NS")
	//if ns == "" {
	//	os.Setenv("DNSUTILS_OVERRIDE_NS", testdata.TEST_NS)
	//}
	c, _ := config.NewConfigFromString(testdata.TEST_KRB5CONF)
	// Set to lookup KDCs in DNS
	c.LibDefaults.DNSLookupKDC = true
	//Blank out the KDCs to ensure they are not being used
	c.Realms = []config.Realm{}

	b, _ := hex.DecodeString(testdata.TESTUSER1_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	cl := NewClientWithKeytab("testuser1", "TEST.GOKRB5", kt, c)

	err := cl.Login()
	if err != nil {
		t.Errorf("error on logging in using DNS lookup of KDCs: %v\n", err)
	}
}
