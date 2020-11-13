<?php
session_start();
include 'Connection.php';

function testInput($input)
{
    $input = stripslashes($input);
    $input = trim($input);
    $input = htmlspecialchars($input);

    return $input;
}

if(isset($_POST['login']))
{
    $email = testInput($_POST['email']);
    $password = testInput($_POST['password']);

    //checking if the input details are empty
    if(empty($email))
    {
        header("Location: /index.php?error= the email field is empty");
    }
    else if(empty($password))
    {
        header("Location: /index.php?error= the password field is empty");
    }
    else
    {
        //dealing with the database
        try
        {
            $stmt = $conn->prepare("SELECT emails,names,passwords,types FROM users WHERE emails=?");
            $stmt->bindValue(1,$email);
            $stmt->execute();

            if($stmt->rowCount())
            {
                while($data = $stmt->fetch(PDO::FETCH_ASSOC))
                {
                    $passwordDb = $data['passwords'];
                    $usernameDb = $data['names'];
                    $typeDb = $data['types'];
                    $phoneDb = $data['phone'];

                    //setting up the session
                    $_SESSION['auth'] = $email;
                    $_SESSION['authType'] = $typeDb;
                    $_SESSION['authName'] = $usernameDb;
                    $_SESSION['authPhone'] = $phoneDb;

                    if(md5($password) == $passwordDb)
                    {
                        //directing different users to their respective pages when validation is true
                        if($typeDb == "admin")
                        {
                            header("Location: /views/admin.blade.php");
                        }
                        else if($typeDb == "client")
                        {
                            header("Location: /views/report.blade.php");
                        }
                        else if($typeDb == "police")
                        {
                            header("Location: /views/police.blade.php");
                        }
                        else
                        {
                            header("Location: /index.php?error=the user type is invalid");
                        }
                    }
                    else
                    {
                        header("Location: /index.php?error=the password do not match our records");
                    }
                }
            }
            else
            {
                header("Location: /index.php?error=the email do not exist in our record");
            }
        }
        catch(PDOException $e)
        {
            header("Location: /index.php?error=".$e->getMessage());
        }
    }
}
else if(isset($_POST['register']))
{
    $name = testInput($_POST['name']);
    $email = testinput($_POST['email']);
    $password = testinput($_POST['password']);
    $password1 = testinput($_POST['secondPassword']);
    $phone = testinput($_POST['phone']);
    $location = testinput($_POST['location']);

    //checking if the fields are filled or not
    if(empty($name))
    {
        header("Location: /index.php?error=the name field is empty");
    }
    else if(empty($email))
    {
        header("Location: /index.php?error=the email field is empty");
    }
    else if(empty($password))
    {
        header("Location: /index.php?error=the password field is empty");
    }
    else if(empty($password1))
    {
        header("Location: /index.php?error=the confirmation password is empty");
    }else if(empty($phone))
    {
        header("Location: /index.php?error=the phone field is empty");
    }
    else if(empty($location))
    {
        header("location: /index.php?error=the location field is empty");
    }
    else
    {
        //checking if the email already exist in the database
        try
        {
            $stmt = $conn->prepare("SELECT emails FROM users WHERE emails=?");
            $stmt->bindValue(1,$email);
            $stmt->execute();

            if($stmt->rowCount())
            {
                header("Location: /index.php?error=the email already exist in our record");
            }
            else
            {
                //checking if the password do match
                if($password == $password1)
                {
                    //encrypting the pass
                    $passwordENC = md5($password);
                    $type = "client";
                    //submiting the email into the db
                    $stmt = $conn->prepare("INSERT INTO users (names,emails,passwords,phone,location,types) 
                        VALUES(:names,:emails,:passwords,:phone,:location,:types)");
                    $stmt->bindParam(":names",$name);
                    $stmt->bindParam(":emails",$email);
                    $stmt->bindParam(":passwords",$passwordENC);
                    $stmt->bindParam(":phone",$phone);
                    $stmt->bindParam(":location",$location);
                    $stmt->bindParam(":types",$type);
                    $rt = $stmt->execute();

                    if($rt > 0)
                    {
                        //setting up the session
                        $_SESSION['auth'] = $email;
                        $_SESSION['authType'] = "client";
                        $_SESSION['authName'] = $name;
                        $_SESSION['authPhone'] = $phone;

                        header("Location: /views/report.blade.php");
                    }
                }
                else
                {
                    header("Location: /index.php?error=the passwords do not match");
                }
            }
        }
        catch(PDOException $e)
        {
            // header("Location: /index.php?error=".$e->getMessage());
            echo $e->getMessage();
        }
    }
}
else
{
    if(!isset($_SESSION['auth']))
    {
        header("Location: /index.php?error=unauthorised page request");
    }
}