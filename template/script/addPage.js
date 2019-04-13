function goBack(){
    location.href = "/";
    return false;
}

function addEditSubmit() {
  $.ajax({
    url: "/addEditSubmit",
    method: "POST",
    data: $("#add-form").serialize(),
    success: function(rawData) {
          $('#add-result').html(rawData);
    }
  });
  return false;
}


function upload() {
  console.log("upload")
  $.ajax({
    url: "/upload",
    method: "POST",
    processData: false, // important
    contentType: false, // important
    data: $("#uploadFile").FormData(),
    success: function(rawData) {
          $('#add-result').html(rawData);
    }
  });
  return false;
}

function uploadFunction() {
	var fd = new FormData();
	var fileInput = document.getElementById('the-file');
	var file = fileInput.files[0];
	var xhr = new XMLHttpRequest();
	xhr.upload.addEventListener('progress', onprogressHandler, false);
	xhr.addEventListener("load", completeHandler, false);
	xhr.addEventListener("error", errorHandler, false);
	xhr.addEventListener("abort", abortHandler, false);
	xhr.open('POST', '/upload');
	fd.append("uploadfile", file);
	xhr.send(fd);
}

function onprogressHandler(event) {
	  document.getElementById("loaded_n_total").innerHTML = "Uploaded " + event.loaded + " bytes of " + event.total;
	  var percent = (event.loaded / event.total) * 100;
	  document.getElementById("progressBar").value = Math.round(percent);
	  document.getElementById("status").innerHTML = Math.round(percent) + "% uploaded... please wait";
	}

function completeHandler(event) {
	  document.getElementById("status").innerHTML = event.target.responseText;
	 // _("progressBar").value = 0; //wil clear progress bar after successful upload
	}

function errorHandler(event) {
	  document.getElementById("status").innerHTML = "Upload Failed";
	}

function abortHandler(event) {
	  document.getElementById("status").innerHTML = "Upload Aborted";
	}
