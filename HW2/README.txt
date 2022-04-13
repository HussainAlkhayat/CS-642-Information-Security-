A Description:
	vulnerabilities: Since URL is executed as given, scripts can be ran in the URL itself without the user knowing. To further explain, the website should not accept input in the URL containing <script> for example. 
			 malicious code can be executed due to this problem
	attack: I will write javascript code, that will send the cookie via email, after the input.
		the website input will look like this: user = ><script> Malicous code </script>
B Description:
	vulnerabilities: the website can be tricked to think that the new page should have access to private information. To further exaplain, the user will log in thus giving the page a cookie for authenticity. A malicious
			 page will open, while the user is on his logged screen, and will be authenticated becuase the page which the user was on was logged in. Then that malicious page can send html form (requests) without 
			 the user knowing
	attack: construct an exact copy of the form that the page (transfer) requires. Input the values such as recipient and value and execute the request without the user's permission. Then go to bing.com to concel what happened
C Description:
	vulnerabilities: Without checking the input values for user and password, They could be injected with malicious sql code that will bypass the sql "WHERE" condition of matching passwords
	attack: construct an exact copy of the form that the page (login page) requires. Input the value of an already registered accound and append "';--" to the user thus the value of the input is "username';--".
		Since the sql querry looks like "SELECT * FROM user_table WHERE user = '$username' AND pass='$password'" our input will make the querry look like this "SELECT * FROM user_table WHERE user = '$username';--" and since the user 		is already registered in this database then the evaluation will be True. the "--" are to comment out everything afterward thus there are not executed. 