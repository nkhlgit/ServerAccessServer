
function goBack(){
    location.href = "/";
    return false;
}

function addEditSubmit() {
  $.ajax({
    url: "/addEditSubmit",
    method: "POST",
    data: $("#edit-form").serialize(),
    success: function(rawData) {
          $('#edit-result').html(rawData);
    }
  });
  return false;
}
