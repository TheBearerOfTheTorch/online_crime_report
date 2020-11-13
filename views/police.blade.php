<?php
    session_start();
    //checking if the session is set
    if(isset($_SESSION['auth']))
    {
        if($_SESSION['authType'] != "police")
        {
            header("Location: /index.php?error=unauthorised page request");
        }
        else
        {
            //end of the first cut
            ?>
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <title>Bootstrap Example</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
                <link href="https://fonts.googleapis.com/css?family=Lobster" rel="stylesheet">
                <link rel="stylesheet" href="path/to/font-awesome/css/font-awesome.min.css">
                <link rel="stylesheet" href="css/font.css" integrity="sha384-50oBUHEmvpQ+1lW4y57PTFmhCaXp0ML5d60M1M7uH2+nqUivzIebhndOJK28anvf" crossorigin="anonymous">
                <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
                <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css" integrity="sha384-50oBUHEmvpQ+1lW4y57PTFmhCaXp0ML5d60M1M7uH2+nqUivzIebhndOJK28anvf" crossorigin="anonymous">
                <style>
                    ul li{}
                    ul li a {color:white;padding:40px; }
                    ul li a:hover {color:white;}
                </style>

            </head>
            <body>

            <nav class="navbar navbar-expand-lg navbar-light bg-light sticky-top">
            
                <a class="navbar-brand" href="index.php"><span style="margin-left:60px;color:green;font-family: 'Permanent Marker', cursive;">POLICE ONLINE</span></a>
                <a class="navbar-brand" style="color:black; text-decoration:none;"><i class="far fa-user"></i></a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                    </button>
                <div class="collapse navbar-collapse" style="margin-left:900px;color:black; text-decoratio:none;" id="navbarResponsive">
                    <a class="nav-link" href="../app/Logout.php">
                        <ul class="navbar-nav ml-auto">
                            <button class="btn btn-outline-success">Log Out</button>
                        </ul>
                    </a>
                </div>
            </nav>
            <!--navbar ends-->
            <br>
            <div class="middle" style="margin-left:150px; padding:40px; border:1px solid #ED2553;  width:80%;">
                <!--tab heading-->
                <ul class="nav nav-tabs nabbar_inverse" id="myTab" style="background:#ED2553;border-radius:10px 10px 10px 10px;" role="tablist">
                    <li class="nav-item">
                        <a class="nav-link active" id="home-tab" data-toggle="tab" href="#viewitem" role="tab" aria-controls="home" aria-selected="true">VIEW CRIMINALS</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" id="profile-tab" data-toggle="tab" href="#manageaccount" role="tab" aria-controls="profile" aria-selected="false">ADD A CRIMINAL</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" id="accountsettings-tab" data-toggle="tab" href="#accountsettings" role="tab" aria-controls="accountsettings" aria-selected="false">VIEW USERS REPORT</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" id="status-tab" data-toggle="tab" href="#status" role="tab" aria-controls="status" aria-selected="false">UPDATE CASE</a>
                    </li>
                    
                </ul>
                <br><br>
                <span style="color:green;"></span>

                <!--tab 1 starts-->   
                <div class="tab-content" id="myTabContent">
                        <div class="tab-pane fade show active" id="viewitem" role="tabpanel" aria-labelledby="home-tab">
                            <div class="container"> 
                                <?php
                                //database connection
                                $servername = '127.0.0.1';
                                $dbname = 'crimereport';
                                $username = 'root';
                                $pass = "";
                                try
                                {
                                    $conn = new PDO("mysql:host=$servername;dbname=$dbname",$username,$pass);
                                    $conn->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);

                                    $stmt = $conn->prepare("SELECT * FROM criminals");
                                    $stmt->execute();

                                    if($stmt->rowCount())
                                    {
                                        while($data = $stmt->fetch(PDO::FETCH_ASSOC))
                                        {
                                            $id = $data['id'];
                                            $criminalname = $data['criminal_name'];
                                            $crimetype = $data['crime_type'];
                                            $aboutcriminal = $data['about_criminal'];
                                            $height = $data['height'];
                                            $weight = $data['weight'];
                                            $photo = $data['criminal_photo'];
                                            $date = $data['created_at'];
                                ?>
                                <table bordercolor="#F0F0F0" cellpadding="20px">
                                <th>criminal image</th>
                                <th>criminal name</th>
                                <th>crime type</th>
                                <th>about the criminal</th>
                                <th>height </th>
                                <th>weight </th>
                                <th>date  </th>
                                <th>criminal id  </th>
                                <tr>           
                                    <td><img src="<?php echo "../app/uploads/$photo" ?>" height="100px" width="150px"></td>
                                    <td style="width:150px;"><?php echo $criminalname;?></td>
                                    <td style="width:150px;"><?php echo $crimetype;?></td>
                                    <td style="width:150px;"><?php echo $aboutcriminal;?></td>
                                    <td style="width:150px;"><?php echo $height;?></td>
                                    <td style="width:150px;"><?php echo $weight;?></td>
                                    <td style="width:150px;"><?php echo $date;?></td>
                                    <td style="width:150px;"><?php echo $id;?></td>
                                </tr>
                                <br>
                                </table>
                                <?php
                                    }
                                }
                            }
                            catch(PDOException $e)
                            {
                                echo "failed to establish a connection with the database. server might be off";
                            }
                        ?>
                            </div>    	 
                        </div>
                        <br>
                        
            <!--tab 1 ends-->	   
                        
                        
                        <!--tab 2 starts-->
                        <div class="tab-pane fade" id="manageaccount" style="width:550px;margin-left:200px;" role="tabpanel" aria-labelledby="profile-tab">
                                <!--add Product-->
                            <form action="../app/Uploads.php" method="post" enctype="multipart/form-data">
                                <div class="form-group"><!--food_name-->
                                <label for="food_name">Criminal name:</label>
                                        <input type="text" class="form-control" id="food_name" value="" placeholder="enter criminal name" name="criminalname" required>
                                </div>
                                <div class="form-group"><!--cost-->
                                        <label for="cost">Crime type :</label>
                                        <input type="text" class="form-control" id="cost"  value="" placeholder="crime type" name="crimetype" required>
                                </div>
                                <div class="form-group"><!--cost-->
                                    <label for="cost">About the criminal :</label>
                                    <input type="text" class="form-control" id="cost"  value="" placeholder="about criminal" name="aboutcriminal" required>
                                </div>
                                <div class="form-group"><!--cost-->
                                    <label for="cost">assume height :</label>
                                    <input type="text" class="form-control" id="cost"  value="" placeholder="hieght" name="height" required>
                                </div>
                                <div class="form-group"><!--cost-->
                                    <label for="cost">assume weight :</label>
                                    <input type="text" class="form-control" id="cost"  value="" placeholder="weight" name="weight" required>
                                </div>
                                <div class="form-group">
                                    <input type="file" accept="image/*" name="image" required/>criminal photo
                                </div>
                                <button type="submit" name="add" class="btn btn-primary">ADD Criminal </button>
                            </form>
                        </div>
                        <!--tab 2 ends-->
                        
                        
                        
                        <div class="tab-pane fade" id="accountsettings" role="tabpanel" aria-labelledby="accountsettings-tab">
                            <table class="table">
                                <!--tab 3-- starts-->
                            <?php
                            //getting the order from the db
                                $stmt= $conn->prepare("SELECT * FROM report_crime ");
                                $stmt->execute();

                                if($stmt->rowCount())
                                {
                                    while($data = $stmt->fetch(PDO::FETCH_ASSOC))
                                    {
                                        $id = $data['id'];
                                        $name = $data['user_name'];
                                        $email = $data['user_email'];
                                        $aboutcriminal = $data['about_criminal'];
                                        $crime = $data['crime_type'];
                                        $date = $data['created_at'];
                                ?>
                                    <tbody>
                                        <th>USER Id</th>
                                        <th>USER Name</th>
                                        <th>USER Email</th>
                                        <th>About criminal</th>
                                        <th>Crime type</th>
                                        <th>Update Status</th>
                                        <tr>
                                            <td><?php echo $id?></td>
                                            <td><?php echo $name?></td>
                                            <td><?php echo $email?></td>
                                            <td><?php echo $aboutcriminal?></td>
                                            <td><?php echo $crime?></td>
                                            <td><?php echo $date?></td>
                                        <tr>
                                    </tbody>
                                <?php
                                    }
                                }
                        ?>
                            </table>
                        </div>
                        
                        
                        <div class="tab-pane fade " id="status" role="tabpanel" aria-labelledby="status-tab">
                            <form action="../app/InputUpdate.php" method="post">
                                <div class="form-group"><!--food_name-->
                                <label for="food_name">case id:</label>
                                        <input type="number" class="form-control" id="food_name" value="" placeholder="enter case id" name="name" required>
                                </div>
                                <div class="form-group"><!--cost-->
                                        <label for="cost">Update case status :</label>
                                        <input type="text" class="form-control" id="cost"  value="" placeholder="write the status of the case" name="status" required>
                                </div>
                                <button type="submit" name="update_status" class="btn btn-primary">update status </button>
                            </form>
                        </div>
                        
                    </div>
                </div>
                <!-- deleting the order or canceling the order -->
                <div class="modal fade" role="dialog" tabindex="-1" id="order_list" style="margin-top: 70px;font-style:normal;">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h4 class="modal-title text-center" style="width: 100%;">Delete food item</h4><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button></div>
                                <div class="modal-body">
                                    <form action="../app/OrderInputs.php" method="post">
                                        <input type="text" class="form-control" id="food_name" value="" placeholder="Enter food number" name="food_number" required>
                                        <button type="submit" name="delete" class="btn btn-danger">Delete food</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="footer-basic" style="margin-left:640px;">
                    <footer>
                        <p class="copyright">CRIME REPORT ONLINE--- The Bearer © 2020</p>
                    </footer>
                </div>
            </body>
            </html>
            <?php
            //beggining
        }
    }
    else
    {
        header("Location: /index.php?error=unauthorised page request");
    }
?>