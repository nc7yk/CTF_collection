package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

type File struct {
	Content string `json:"content" binding:"required"`
	Name string `json:"name" binding:"required"`
}
type Url struct {
	Url string `json:"url" binding:"required"`
}

func md5sum(data string) string{
	s := md5.Sum([]byte(data))
	return hex.EncodeToString(s[:])
}




func fileMidderware (c *gin.Context){
	fileSystem := http.Dir("./files/")
	if c.Request.URL.String() == "/"{
		c.Next()
		return
	}
	f,err := fileSystem.Open(c.Request.URL.String())
	if f == nil {
		c.Next()
	}
	//
	if err != nil {
		c.Next()
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if  err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if fi.IsDir() {

		if !strings.HasSuffix(c.Request.URL.String(), "/") {
			c.Redirect(302,c.Request.URL.String()+"/")
		} else {
			files := make([]string,0)
			l,_ := f.Readdir(0)
			for _,i := range l {
				files = append(files, i.Name())
			}

			c.JSON(http.StatusOK, gin.H{
				"files" :files,
			})
		}


	} else {
		data,_ := ioutil.ReadAll(f)
		c.Header("content-disposition", `attachment; filename=` + fi.Name())
		c.Data(200, "text/plain", data)
	}

}

func uploadController(c *gin.Context) {
	var file File
	if err := c.ShouldBindJSON(&file); err != nil {
		c.JSON(500, gin.H{"msg": err})
		return
	}

	dir := md5sum(file.Name)

	_,err:= http.Dir("./files").Open(dir)
	if err != nil{
		e := os.Mkdir("./files/"+dir,os.ModePerm)
		_, _ = http.Dir("./files").Open(dir)
		if e != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": e.Error()})
			return

		}

	}
	filename := md5sum(file.Content)
	path := "./files/"+dir+"/"+filename
	err = ioutil.WriteFile(path, []byte(file.Content), os.ModePerm)
	if err != nil{
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"message": "file upload succ, path: "+dir+"/"+filename,
	})
}
func vulController(c *gin.Context) {

	var url Url
	if err := c.ShouldBindJSON(&url); err != nil {
		c.JSON(500, gin.H{"msg": err})
		return
	}

	if !strings.HasPrefix(url.Url,"http://127.0.0.1:1234/"){
		c.JSON(403, gin.H{"msg": "url forbidden"})
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}

	resp, err := client.Get(url.Url)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	var buffer [512]byte
	result := bytes.NewBuffer(nil)
	for {
		n, err := resp.Body.Read(buffer[0:])
		result.Write(buffer[0:n])
		if err != nil && err == io.EOF {

			break
		} else if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": result.String()})
}
func main() {
	r := gin.Default()
	r.Use(fileMidderware)
	r.POST("/vul",vulController)
	r.POST("/upload",uploadController)
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	_ = r.Run(":1234") // listen and serve on 0.0.0.0:8080
}
