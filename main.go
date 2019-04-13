package main

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/satori/go.uuid"

	"github.com/gorilla/mux"

	"github.com/gomodule/redigo/redis"
	_ "github.com/lib/pq"
)

var cache redis.Conn

const (
	DB_USER     = "dcadmin"
	DB_PASSWORD = "dcadmin"
	DB_NAME     = "dc"
)

var dbinfo = fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable",
	DB_USER, DB_PASSWORD, DB_NAME)

//sever struct contains the server properties
type server struct {
	SrvId                string
	Name                 string
	IP                   string
	Hostname             string
	OsUser               string
	OsPassword           string
	OsPort               string
	WebPort              string
	Product              string
	Datacenter           string
	WebPrefix            string
	WebSuffix            string
	Fav                  string
	DateTimeLastAccessed string
}

// chkErr is common function for any error
func chkErr(err error) {
	if err != nil {
		panic(err)
	}
}

// intialize redis cache
func initCache() {
	// Initialize the redis connection to a redis instance running on your local machine
	conn, err := redis.DialURL("redis://localhost")
	if err != nil {
		panic(err)
	}
	// Assign the connection to the package level `cache` variable
	cache = conn
}

// template for index page
var templates = template.Must(template.ParseFiles("./template/index.html"))
var templates1 = template.Must(template.ParseFiles("./template/addPage.html"))
var templates2 = template.Must(template.ParseFiles("./template/editPage.html"))
var templates3 = template.Must(template.ParseFiles("./template/signin.html"))

// index function habled first index function/ #Page
func index(w http.ResponseWriter, r *http.Request) {
	sessionChk(w, r)
	if err := templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

//user information
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct that models the structure of a user, both in the request body, and in the DB
type Credentials struct {
	Password string
	Username string
}

// Singnin #page
func signin(w http.ResponseWriter, r *http.Request) {
	//Check if this is a "GET" or "POST" request
	if r.Method == http.MethodGet {
		if err := templates3.ExecuteTemplate(w, "signin.html", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
	if r.Method == "POST" {
		// For all request except "GET"
		r.ParseForm()
		var creds Credentials
		// checkif username is provided, if yes, Check length, then assin to struct. Repeat same for Password
		if _, ok := r.Form["Username"]; ok {
			if len(r.Form["Username"][0]) > 0 {
				creds.Username = r.Form["Username"][0]
			}
		}
		if _, ok := r.Form["Password"]; ok {
			if len(r.Form["Password"][0]) > 0 {
				creds.Password = r.Form["Password"][0]
			}
		}

		// Get the expected password from our in memory map
		expectedPassword, ok := users[creds.Username]
		// If a password exists for the given user
		// AND, if it is the same as the password we received, the we can move ahead
		// if NOT, then we return an "Unauthorized" status
		if !ok || expectedPassword != creds.Password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Create a new random session token
		sessionToken := uuid.Must(uuid.NewV4()).String()
		// Set the token in the cache, along with the user whom it represents
		// The token has an expiry time of 120 seconds
		_, err := cache.Do("SETEX", sessionToken, "1200", creds.Username)
		if err != nil {
			// If there is an error in setting the cache, return an internal server error
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Finally, we set the client cookie for "session_token" as the session token we just generated
		// we also set an expiry time of 120 seconds, the same as the cache
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(120 * time.Second),
		})
	}
}

// session Check sessions. #page
func sessionChk(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			http.Redirect(w, r, "/signin", 302)

		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value
	// We then get the name of the user from our cache, where we set the session token
	response, err := cache.Do("GET", sessionToken)
	if err != nil {
		// If there is an error fetching from cache, return an internal server error status
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if response == nil {
		// If the session token is not present in cache, return an unauthorized error
		http.Redirect(w, r, "/signin", 302)
		return
	}
	return
}

//function addPage show add server page. #page
func addPage(w http.ResponseWriter, r *http.Request) {
	sessionChk(w, r)
	if err := templates1.ExecuteTemplate(w, "addPage.html", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// search function Query SQL and upload data/ #page
func search(w http.ResponseWriter, r *http.Request) {
	sessionChk(w, r)
	var result server
	var results []server
	filterStr := ""
	firstArg := true
	// get the form data entered in search-form with name "search"
	r.ParseForm()
	for key, value := range r.Form {
		if len(value[0]) > 0 {
			if firstArg {
				filterStr = filterStr + " WHERE "
				firstArg = false
			} else {
				filterStr = filterStr + " AND "
			}
			filterStr = filterStr + " " + key + " like '%" + value[0] + "%'"
		}

	}
	//columns refered from sql server
	selectColumns := "srvId,name,ip,hostname,product,datacenter,dateTimeLastAccessed"
	queryString := "SELECT " + selectColumns + " FROM servers " +
		filterStr + " ORDER BY dateTimeLastAccessed DESC"
	// Open sqlite connection for dc.db. The table the data should be cretaed using csv_to_sql.go tool
	db, _ := sql.Open("postgres", dbinfo)
	rows, err := db.Query(queryString)
	chkErr(err)
	var dateTime time.Time
	for rows.Next() {
		err = rows.Scan(&result.SrvId, &result.Name, &result.IP, &result.Hostname, &result.Product,
			&result.Datacenter, &result.DateTimeLastAccessed)

		dateTime, err = time.Parse(time.RFC3339, result.DateTimeLastAccessed)
		chkErr(err)
		result.DateTimeLastAccessed = dateTime.Format("2006-Jan-02 15:04:05")
		results = append(results, result)
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(results); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	db.Close()
	return
}

//Upload the data in bulk #Page
func upload(w http.ResponseWriter, r *http.Request) {
	// add http request file to memeory
	r.ParseMultipartForm(32 << 20)
	//open the form file
	csvFile, _, err := r.FormFile("uploadfile")
	chkErr(err)
	defer csvFile.Close()
	reader := csv.NewReader(csvFile)
	reader.FieldsPerRecord = -1
	csvData, err := reader.ReadAll()
	chkErr(err)
	//strip header ;and  send csvDada as string [][].
	res := addServerDb(csvData[1:])
	//write response to hrrp response
	w.Write([]byte(res))
	return
}

// Delete server detele Server from database/ #page
func deleteServer(w http.ResponseWriter, r *http.Request) {
	sessionChk(w, r)
	//create struct to match the reciving data
	type deleteData struct {
		DelSrvId string
	}
	var t deleteData
	//decode the recived reeq body in json format
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&t)
	chkErr(err)
	db, _ := sql.Open("postgres", dbinfo)
	sqlstatement := "DELETE FROM servers WHERE SrvId = $1"
	_, err = db.Exec(sqlstatement, t.DelSrvId)
	var res string
	if err != nil {
		res = err.Error()
	} else {
		res = "Server " + t.DelSrvId + " is deleted."
	}
	w.Write([]byte(res))
	db.Close()
	return
}

// edit #page load edit page for server
func editPage(w http.ResponseWriter, r *http.Request) {
	sessionChk(w, r)
	type editData struct {
		EdtSrvId string
	}
	var t editData
	//decode the recived reeq body in json format
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&t)
	chkErr(err)
	db, _ := sql.Open("postgres", dbinfo)
	var result server
	selectColumns := "srvId,name,ip,hostname,osUser,osPassword,osPort," +
		"webPort,product,datacenter,webPrefix,webSuffix,fav"
	queryString := "SELECT " + selectColumns + " FROM servers where srvId =" + t.EdtSrvId
	rows, err := db.Query(queryString)
	chkErr(err)
	for rows.Next() {
		err = rows.Scan(&result.SrvId, &result.Name, &result.IP, &result.Hostname, &result.OsUser,
			&result.OsPassword, &result.OsPort, &result.WebPort, &result.Product, &result.Datacenter, &result.WebPrefix, &result.WebSuffix, &result.Fav)
		chkErr(err)
		if result.Fav == "true" {
			result.Fav = "checked"
		} else {
			result.Fav = ""
		}
	}
	if err := templates2.Execute(w, result); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// function addServerDb add string to database used in addSubmit and upload dunctions
func addServerDb(ss [][]string) (res string) {
	res = "Server added: "
	db, err := sql.Open("postgres", dbinfo)
	chkErr(err)
	defer db.Close()
	sqlstatement := `
	INSERT INTO servers (name,ip,hostname,osUser,osPassword,osPort,webPort,product,datacenter,webPrefix,webSuffix,fav, dateTimeCreated, dateTimeModified,dateTimeLastAccessed ) 
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	chkErr(err)
	var timeNow string
	timeNow = "NOW()"
	for _, s := range ss {
		/*
			s[0] = Name, s[1] = IP, s[2] = Hostname, s[3] = OsUser, s[4] = OsPassword, s[5] = OsPort, s[6] = WebPort,
			s[7]=Product, s[8]=Datacenter, s[9]=WebPrefix, s[10]=WebSuffix, s[11]=Fav, timeNow = dateTimeCreated,
			 timeNow = dateTimeModified, timeNow = dateTimeLastAccessed
		*/
		_, err = db.Exec(sqlstatement, s[0], s[1], s[2], s[3], s[4], s[5], s[6],
			s[7], s[8], s[9], s[10], s[11], timeNow, timeNow, timeNow)
		if err != nil {
			res = res + " " + err.Error()
		} else {
			res = res + " " + s[0]
		}
	}
	return res
}

// function addServerDb add string to database used in addSubmit and upload dunctions
func editServerDb(ss [][]string, srvId string) (res string) {
	res = "Server data modified: "
	db, _ := sql.Open("postgres", dbinfo)
	dbQueryString := `UPDATE servers SET name=$1,ip=$2,hostname=$3,osUser=$4,osPassword=$5,osPort=$6,
		webPort=$7,product=$8,datacenter=$9,webPrefix=$10,webSuffix=$11,fav=$12 where srvId =$13`
	for _, s := range ss {
		/*
			srvId = SrvId,s[0] = Name, s[1] = IP, s[2] = Hostname, s[3] = OsUser, s[4] = OsPassword, s[6] = OsPort, s[7] = WebPort,
			s[8]=Product, s[9]=Datacenter, s[10]=WebPrefix, s[11]=WebSuffix, s[12]=Fav
		*/
		_, err := db.Exec(dbQueryString, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10], s[11], srvId)
		if err != nil {
			res = res + " " + err.Error()
		} else {
			res = res + " " + s[0]
		}
	}
	db.Close()
	return res
}

//Submit the edit #Page
func addEditSubmit(w http.ResponseWriter, r *http.Request) {
	sessionChk(w, r)
	// get the form data entered in add-form with name as in form
	r.ParseForm()
	//Converint checked input to /true/false
	favBool := "false"
	if _, ok := r.Form["fav"]; ok {
		if strings.EqualFold(r.Form["fav"][0], "true") || r.Form["fav"][0] == "on" {
			favBool = "true"
		}
	}
	fmt.Print("%v", r.Form)
	s := []string{r.Form["name"][0],
		r.Form["ip"][0], r.Form["hostname"][0], r.Form["osUser"][0], r.Form["osPassword"][0], r.Form["osPort"][0], r.Form["webPort"][0], r.Form["product"][0],
		r.Form["datacenter"][0], r.Form["webPrefix"][0], r.Form["webSuffix"][0], favBool}

	// define two dimention array 'ss'
	ss := make([][]string, 1)
	ss[0] = s
	// send ss to add to db
	res := ""
	switch r.Form["reqType"][0] {
	case "add":
		res = addServerDb(ss)
	case "edit":
		res = editServerDb(ss, r.Form["srvId"][0])
	}
	//write response
	w.Write([]byte(res))
	return
}

func getProperties() (saProp map[string]interface{}) {

	jsonFile, err := os.Open("saProperties.json")
	chkErr(err)
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &saProp)

	if _, ok := saProp["selfLaunch"]; !ok {
		saProp["SelfLaunch"] = "true"
	}
	if _, ok := saProp["webPort"]; !ok {
		saProp["webPort"] = "8080"
	}

	return saProp
}

func logoff(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			http.Redirect(w, r, "/signin", 302)

		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sessionToken := c.Value
	// We then get the name of the user from our cache, where we set the session token
	_, err = cache.Do("DEL", sessionToken)
	log.Println(err)
	if err != nil {
		// If there is an error fetching from cache, return an internal server error status
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/signin", 302)
	return
}

func initPostgres() {
	db, err := sql.Open("postgres", dbinfo)
	chkErr(err)
	defer db.Close()
	sqlstatement := `CREATE TABLE IF NOT EXISTS servers (srvId BIGSERIAL PRIMARY KEY, name VARCHAR (20),
		ip VARCHAR (20),hostname VARCHAR (20),osUser VARCHAR (20),osPassword VARCHAR (20),osPort VARCHAR (20),
		webPort VARCHAR (20),product VARCHAR (20),datacenter VARCHAR (20),webPrefix VARCHAR (20),
		webSuffix VARCHAR (20), fav VARCHAR (20), dateTimeCreated timestamp, dateTimeModified timestamp,
		dateTimeLastAccessed timestamp)`

	_, err = db.Exec(sqlstatement)
	chkErr(err)

	sqlstatement = `CREATE TABLE users(
		user_id serial PRIMARY KEY,
		username VARCHAR (50) UNIQUE NOT NULL,
		password VARCHAR (50) NOT NULL,
		level int4  NOT NULL,
		email VARCHAR (355),
		Phone VARCHAR (50),
		enabled  boolean DEFAULT 't',
		created_on TIMESTAMP NOT NULL,
		last_login TIMESTAMP
	   )`
	_, err = db.Exec(sqlstatement)
	chkErr(err)

	var userid int
	err = db.QueryRow("select user_id from users where username = ?", 1).Scan(&userid)
	chkErr(err)

	if userid < 1 {
		sqlstatement = `INSERT into users (username, password, level, created_on ) VALUES ('admin', 'admin01', 5, 'now' )
	 WHERE  user_id < 1 )`
		_, err = db.Exec(sqlstatement)
		chkErr(err)
	}
}

func main() {
	initCache()
	initPostgres()
	var saProp map[string]interface{}
	saProp = getProperties()
	fmt.Println(saProp)
	webPort := ":" + saProp["webPort"].(string)
	r := mux.NewRouter()
	r.HandleFunc("/", index)
	r.HandleFunc("/signin", signin)
	r.HandleFunc("/search", search)
	//r.HandleFunc("/connect", connect)
	r.HandleFunc("/addPage", addPage)
	r.HandleFunc("/deleteServer", deleteServer)
	r.HandleFunc("/upload", upload)
	r.HandleFunc("/editPage", editPage)
	r.HandleFunc("/addEditSubmit", addEditSubmit)
	r.HandleFunc("/logoff", logoff)
	//Specifying the http file location for CSS
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./template/")))
	http.Handle("/", r)
	myhost, err := os.Hostname()
	chkErr(err)
	myhttpsStr := `https://` + myhost + `:8443/`
	go http.ListenAndServe(webPort, http.RedirectHandler(myhttpsStr, 301))
	log.Println(http.ListenAndServeTLS(":8443", "/opt/certs/selfSign/jan20SlfCrt.pem", "/opt/certs/selfSign/jan20SlfKey.pem", nil))
}
