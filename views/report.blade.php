<?php
    session_start();
    //checking if the session is set
    if(isset($_SESSION['auth']))
    {
        if($_SESSION['authType'] != "client")
        {
            header("Location: /index.php?error=unauthorised page request");
        }
        else
        {
            //end of the first cut
        ?>
        <!DOCTYPE html>
        <html lang="en" >
        <html>
            <head>
                <title>REPORT CRIME OLINE</title>
                <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
                <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
                <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
                <link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.8.1/css/all.css" integrity="sha384-50oBUHEmvpQ+1lW4y57PTFmhCaXp0ML5d60M1M7uH2+nqUivzIebhndOJK28anvf" crossorigin="anonymous">   
                <style>
                    ul li{}
                    ul li a {color:black;}
                    ul li a:hover {color:black; font-weight:bold;}
                    ul li {list-style:none;}

                    ul li a:hover{text-decoration:none;}
                    #social-fb,#social-tw,#social-gp,#social-em{color:blue;}
                    #social-fb:hover{color:#4267B2;}
                    #social-tw:hover{color:#1DA1F2;}
                    #social-gp:hover{color:#D0463B;}
                    #social-em:hover{color:#D0463B;}
                </style>
            </head>
            <body>
                <!-- navbar -->
                <nav class="navbar navbar-expand-lg navbar-light bg-light sticky-top">
                    <div class="container">
                        <a class="navbar-brand" href="index.php"><span style="color:green;font-family: 'Permanent Marker', cursive;">online crime report </span></a>
                        
                        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
                            <span class="navbar-toggler-icon"></span>
                            </button>
                            <div class="collapse navbar-collapse" id="navbarCollapse">
                        <!-- this for the drop down -->
                            <button
                                data-toggle="collapse" class="navbar-toggler collapsed" data-target="#navcol-1">
                                <span>MENU</span>
                            </button>
                            <div class="collapse navbar-collapse text-center" id="navcol-1">
                                <ul class="nav navbar-nav ml-auto">
                                    <li class="nav-item" role="presentation"><a class="nav-link" href="#"><i class="far fa-bell" style="font-size: 23px;"></i></a></li>
                                    <li class="dropdown nav-item">
                                        <a class="dropdown-toggle nav-link" data-toggle="dropdown" aria-expanded="false" href="#">Profile</a>
                                        <div class="dropdown-menu text-center" style="color:white" role="menu">
                                            <a class="dropdown-item" role="presentation" href="../app/Logout.php">Logout</a>
                                        </div>
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </nav>
                <!--navbar ends-->

                <!--details section-->
                <div class="container" style="margin-top:20px;">
                    <!--tab 1 starts checking for the status of the case-->
                    <a id="director_rejobs_link" href="#" data-target="#manageaccount" data-toggle="modal" style="margin-left:50px;">
                        <button type="button" class="btn btn-danger"><h4>Check your case status</h4> </button>
                    </a>
                    <a id="director_rejobs_link" href="#" data-target="#order_list" data-toggle="modal" style="margin-left:450px;">
                        <button type="button" class="btn btn-danger"><h4>Report a crime online</h4> </button>
                    </a>
                    <div class="tab-content" id="myTabContent">
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
                    
                        <div class="tab-pane fade show active" style="margin-top:30px;" id="viewitem" role="tabpanel" aria-labelledby="viewitem-tab">
                            <div class="container">
                                <div class="card">
                                    <div class="card-header" style="margin-left:340px;margin-right:330px;">
                                        <h3>criminal details below </h3>
                                    </div>
                                    <div class="card-body" style="margin-left:160px;hight:100px;">
                                        <table bordercolor="#F0F0F0" cellpadding="20px">
                                            <th>photo</th>
                                            <th>personal details</th>
                                            <tr>
                                                <td style="width:350px;"><img src="<?php echo "../app/uploads/$photo" ?>" height="140px" width="190px"></td>
                                                <td style="width:350px;">
                                                    <b>Id:</b> <?php echo $id;?> <br>
                                                    <b>name:</b> <?php echo $criminalname;?><br>
                                                    <b>crime type:</b> <?php echo $crimetype;?><br>
                                                    <b>about criminal:</b> <?php echo $aboutcriminal;?><br>
                                                    <b>height:</b> <?php echo $height?><br>
                                                    <b>weight:</b> <?php echo $weight?><br>
                                                    <b>date of conviction:</b> <?php echo $date?><br>
                                                </td>
                                            </tr>
                                            <br>
                                            </table>
                                    </div>
                                </div>
                            </div> 
                            
                            <span style="color:green; text-align:centre;"></span>
                        </div>
                        <?php
                                    }
                                }
                            }
                            catch(PDOException $e)
                            {
                                echo "failed to establish a connection with the database. server might be off";
                                echo $e->getMessage();
                            }

                        ?>
                        <!--tab 1 ends-->
                            
                        <!--tab 2 starts-->
                        <div class="modal fade" role="dialog" tabindex="-1" id="manageaccount" style="margin-top:50px;" role="tabpanel" aria-labelledby="manageaccount-tab">
                            <div class="modal-dialog" role="document">
                                <div class="modal-content">
                                    <div class="modal-header">
                                        <h4 class="modal-title text-center" style="width: 100%;">Check for your case status</h4><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button></div>
                                        <div class="modal-body">
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
                                                        
                                                        //
                                                        $stmt = $conn->prepare("SELECT * FROM report_status ");
                                                        $stmt->execute();

                                                        if($stmt->rowCount())
                                                        { 
                                                            while($data = $stmt->fetch(PDO::FETCH_ASSOC))
                                                            {
                                                                $status = $data['case_status'];
                                                                $caseid = $data['case_id'];
                                                                $username = $data['user_name'];

                                                                //logic for checking the case status

                                                ?>
                                                    <table class="table">
                                                        <tbody>
                                                            <th>Your Case Id</th>
                                                            <th>case status</th>
                                                            <tr>
                                                                <td><?php echo $caseid;?></td>
                                                                <td>
                                                                    <?php 
                                                                        if($status == "pending")
                                                                        {
                                                                            ?>
                                                                            <button type="submit" name="report" class="btn btn-warning">case still pending</button>
                                                                            <?php   
                                                                        }
                                                                        else if($status == "dismissed")
                                                                        {
                                                                            ?>
                                                                            <button type="submit" name="report" class="btn btn-dark">case was dismissed</button>
                                                                            <?php   
                                                                        }
                                                                        else if($status == "closed")
                                                                        {
                                                                            ?>
                                                                            <button type="submit" name="report" class="btn btn-light">case was closed and suspect convicted</button>
                                                                            <?php   
                                                                        }
                                                                        else if($status == "investigation")
                                                                        {
                                                                            ?>
                                                                            <button type="submit" name="report" class="btn btn-primary">started investigation on the case</button>
                                                                            <?php   
                                                                        }
                                                                        else {
                                                                            ?>
                                                                            <button type="submit" name="report" class="btn btn-danger">The case is not yet assigned</button>
                                                                            <?php
                                                                        }
                                                                    ?>
                                                                </td>
                                                            <tr>
                                                        </tbody>
                                                    </table>
                                                <?php
                                                            }
                                                        }
                                                    }
                                                    catch(PDOException $e)
                                                    {
                                                        echo "failed to establish a connection with the database. server might be off";
                                                        echo $e->getMessage();
                                                    }

                                                ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- writing the report -->
                <div class="modal fade" role="dialog" tabindex="-1" id="order_list" style="margin-top: 70px;font-style:normal;">
                    <div class="modal-dialog" role="document">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h4 class="modal-title text-center" style="width: 100%;">Report a crime by filling the fields below</h4><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">×</span></button></div>
                                <div class="modal-body">
                                    <form action="../app/InputUpdate.php" method="post">
                                        <input type="text" class="form-control" id="food_name" value="" placeholder="write a brief description about the suspect" name="aboutcriminal" required><br>
                                        <input type="text" class="form-control" id="food_name" value="" placeholder="Enter crime committed" name="crimetype" required><br>
                                        <button type="submit" name="report" class="btn btn-warning">submit report</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="footer-basic" style="margin-left:500px;">
                    <footer>
                        <p class="copyright">CRIME REPORT ONLINE--- The Bearer © 2020</p>
                    </footer>
                </div>
            <?php
            //beggining
        }
    }
    else
    {
        header("Location: /index.php?error=unauthorised page request");
    }
?>