package gtp5gnl

import (
	"github.com/khirono/go-genl"
	"github.com/khirono/go-nl"
)

type Client struct {
	Client *nl.Client
	ID     int
}

func NewClient(conn *nl.Conn, mux *nl.Mux) (*Client, error) {
	c := new(Client)
	c.Client = nl.NewClient(conn, mux)
	f, err := genl.GetFamily(c.Client, "gtp5g")
	if err != nil {
		return nil, err
	}
	c.ID = int(f.ID)
	return c, nil
}

func (c *Client) Do(req *nl.Request) ([]nl.Msg, error) {
	// WNC: Use test hook if set (for testing netlink request serialization)
	if testClientDoHook != nil {
		return testClientDoHook(req)
	}
	return c.Client.Do(req)
}
