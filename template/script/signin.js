function loginSubmit() {
  $.ajax({
    url: "/signin",
    method: "POST",
    data: $("#signin-form").serialize(),
    success: function(rawData) {
      $('#login-message').html("Autanticated...Logging in...");
         location.href = "/";
			return false;
    },
    error: function(xhr, status, error) {
      if (xhr.status == 401){
        $('#login-message').html("Entered credentials are incorrect.");
      } else if (xhr.status == 500) {
          $('#login-message').html("Server error: 500. Contact your Administrator");
    }
  }
  });
  return false;
}
