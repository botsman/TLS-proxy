package main

func main() {
	proxy := Proxy{
		GcloudKeyLoader{},
	}
	err := proxy.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
