var serverID = "";

//defne the behaviour upon selecting row. resultID is from onclick function of row
function rowSelect(resultID){
            //IDsel = "#"+resultID
			// tr id of row is my+ServerID
            myidStr = "#my" + resultID
			// set calass of selected row as selected and remove from other
            $(myidStr).addClass('selected').siblings().removeClass('selected');
			// serverID is global variable of resultID
            serverID = resultID;
                        return false;
}


function queryFunc(){
   $("#search-form").toggle();
   //e.preventDefault();
    $("#hide").toggle();
    $("#show").toggle();
   return false;
}

function submitSearch() {
  var searchResults = $("#search-results");
  searchResults.empty();
  $.ajax({
    url: "/search",
    method: "POST",
    data:  $("#search-form").serialize(),
    success: function(rawData) {
      var parsed = JSON.parse(rawData);
      if (!parsed) return;
      parsed.forEach(function(result) {
          var row = $('<tr id="my' + result.SrvId + '" onclick="rowSelect(' + result.SrvId +
           ')"><td>' + result.SrvId + "</td><td>" + result.Name +
           "</td><td>" + result.IP + "</td><td>" + result.Hostname + "</td><td>" + result.Product +
           "</td><td>" + result.Datacenter + "</td><td>" + result.DateTimeLastAccessed + "</td></tr>");
          searchResults.append(row);
        });
      }
    });
  return false;
}

 // Load the all list upon page loadup.
$( document ).ready(submitSearch);



function access( accessMode ){
	//set serverID as string type.
             serverID  = serverID + "";
            var accessData = {
              SID: serverID,
              Type: accessMode
            };

            $.ajax({
              url: "/connect",
              method: "POST",
              dataType: "json",
              contentType: "application/json; charset=utf-8",
              data: JSON.stringify(accessData)
            });
              return false;
}
function addPage(){
    location.href = "/addPage";
    return false;
}

function deleteServer(){
	//convert to string
	var result = confirm("Want to delete?");
	if (result) {
		serverID  = serverID + "";
		//create jsone data to send
		var deleteData = {DelSrvId: serverID}
			$.ajax({
            url: "/deleteServer",
            method: "POST",
			  // As received data is not in jsone format. commented out
              //dataType: "json",
            contentType: "application/json; charset=utf-8",
            data: JSON.stringify(deleteData),
			      success: function(rawData) {
				          data = "Update: " + rawData
					        $('#message').html(data);
					        myidStr = "#my" + serverID
					      // set calass of selected row as selected and remove from other
					       $(myidStr).removeClass('selected');
					       $(myidStr).hide();
			         }
            });
    	}
	return false;
}

function editServer(){
  serverID  =  serverID + "";
  var editData = {EdtSrvId: serverID}
  $.ajax({
          url: "/editPage",
          method: "POST",
    // As received data is not in jsone format. commented out
          //dataType: "json",
          contentType: "application/json; charset=utf-8",
          data: JSON.stringify(editData),
     success: function(rawData) {
       //$("html").empty();
       my_window = window.open("","_self");
       my_window.document.write(rawData);
     }
        });
return false;
}

function allFav(){
    var x = document.getElementById("sDiv");
      var y = document.getElementById("fav-query");
      var z = document.getElementById("fav-view");
      if (x.innerHTML === "Show-All") {
          x.innerHTML = "Show-Fav";
          y.value = "e";
          z.innerHTML = "View-All";

      } else {
          x.innerHTML = "Show-All";
          y.value = "true";
          z.innerHTML = "Fav-Only";
        }
        submitSearch();
 return false;
}


function logoff(){
  location.href = "/logoff";
  return false;
  }
