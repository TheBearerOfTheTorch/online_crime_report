<!DOCTYPE html>
<html lang="en" >
<html>
    <head>
    <meta charset="UTF-8">
        <title>crime report</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
            <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
            <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css" integrity="sha384-50oBUHEmvpQ+1lW4y57PTFmhCaXp0ML5d60M1M7uH2+nqUivzIebhndOJK28anvf" crossorigin="anonymous">
            
            <style>
            ul li{list-style:none;}
            ul li a {color:black;font-weight:bold;text-decoration:none; }
            ul li a:hover {color:black;text-decoration:none;}
            </style>
    </head>
    <body>
        <nav class="navbar navbar-expand-lg navbar-light bg-light sticky-top ">
            <a class="navbar-brand" href="../index.php"><span style="color:#ED2553;font-family: 'Permanent Marker', cursive;">ONLINE CRIME REPORT</span></a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
                </button>
            <div class="collapse navbar-collapse" id="navbarResponsive">
            
            <ul class="navbar-nav ml-auto">
                <li class="nav-item active">
                <a class="nav-link" href="../index.php" style="color:#BDDEFD">Home
                        
                    </a>
                </li>
                <li class="nav-item">
                <a class="nav-link" href="../aboutus.php" style="color:#BDDEFD">About</a>
                </li>
                <li class="nav-item">
                <a class="nav-link" href="../services.php" style="color:#BDDEFD">Services</a>
                </li>
                <li class="nav-item">
                <a class="nav-link" href="../contact.php" style="color:#BDDEFD">Contact</a>
                </li>
            </ul>
            </div>
        </nav>
        <br><br><br>
        <div class="middle" style="padding:20px;margin-bottom:20px; border:1px solid #ED2553; margin:0px auto;width:400px;">
            <ul class="nav nav-tabs nabbar_inverse" id="myTab" style="background:#ED2553;border-radius:10px 10px 10px 10px;" role="tablist">
                <li class="nav-item">
                    <a class="nav-link active" style="color:#BDDEFD;" id="login-tab" data-toggle="tab" href="#login" role="tab" aria-controls="login" aria-selected="true">Log In</a>
                </li>
                <li class="nav-item">
                    <a class="nav-link" id="signup-tab" style="color:#BDDEFD;" data-toggle="tab" href="#signup" role="tab" aria-controls="signup" aria-selected="false">Create New Account</a>
                </li>
            </ul>
            <br>
            <div class="tab-content" id="myTabContent">
                <!--login Section-- starts-->
                <div class="tab-pane fade show active" id="login" role="tabpanel" aria-labelledby="home-tab">
                    <div class="footer" style="color:red;"></div>
                    <form method="POST" action="app/Validation.php">
                        <div class="form-group">
                            <label for="email">Email address:</label>
                            <input type="email" class="form-control" name="email" id="email" required/>
                        </div>
                        <div class="form-group">
                            <label for="pwd">Password:</label>
                            <input type="password" name="password" class="form-control" id="pwd" required/>
                        </div>
        
                        <button type="submit" name="login" style="background:#ED2553; border:1px solid #ED2553;" class="btn btn-primary">Login</button>
                        <div class="footer" style="color:red;"></div>
                    </form>
                </div>
                <!--login Section-- ends-->
                    
                <!--new account Section-- starts-->
                <div class="tab-pane fade" id="signup" role="tabpanel" aria-labelledby="profile-tab" >
                    <form method="POST" action="app/Validation.php">
                        <div class="form-group">
                        <label for="name">Name</label>
                        <input type="text" id="name"  class="form-control" name="name" required="required"/>
                        </div>
                        
                        <div class="form-group">
                        <label for="email">Email</label>
                        <input type="email" id="email" name="email" class="form-control" value="" required="required"/>
                        </div>
                            
                        <div class="form-group">
                            <label for="pwd">Password:</label>
                            <input type="password" name="password" class="form-control" id="pwd" required/>
                        </div>
                        <div class="form-group">
                            <label for="pwd">Confirm Password:</label>
                            <input type="password" name="secondPassword" class="form-control" id="pwd" required/>
                        </div>
                        
                        <div class="form-group">
                            <label for="phone">Phone</label>
                            <input type="phone" id="phone" class="form-control" name="phone" placeholder="" required>
                        </div>
                            
                        <div class="form-group">
                            <label for="mobile">Location</label>
                            <input type="text" id="location" class="form-control" name="location"  placeholder="" required>
                        </div>
                        <button type="submit" name="register" style="background:#ED2553; border:1px solid #ED2553;" class="btn btn-primary">Create New Account</button>
                        <div class="footer" style="color:red;"></div>
                    </form>
                </div>
            </div>
        </div>
    </body>
</html>
