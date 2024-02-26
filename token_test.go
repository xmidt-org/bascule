package bascule

type testToken struct {
	principal string
}

func (tt *testToken) Principal() string {
	return tt.principal
}
