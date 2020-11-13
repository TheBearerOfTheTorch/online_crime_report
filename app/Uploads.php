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

if(isset($_SESSION['auth']))
{
    if($_SESSION['authType'] != "police")
    {
        header("Location: /index.php?error= this is an annonymous page");
    }
    else
    {
        //getting the inputs

        $criminalname =testInput($_POST['criminalname']);
        $crimetype = testInput($_POST['crimetype']);
        $aboutcrime = testInput($_POST['aboutcriminal']);
        $weight = testInput($_POST['weight']);
        $height = testInput($_POST['height']);
        $image = $_FILES['image']['name'];

        if(empty($criminalname))
        {
            header("Location: ../views/police.blade.php?error=the name field is empty please dare to fill it up");
        }
        else if(empty($crimetype))
        {
            header("Location: ../views/police.blade.php?error=the crime type field is empty");
        }
        else if(empty($aboutcrime))
        {
            header("Location: ../views/police.blade.php?error=the about crime field is empty");
        }
        else if(empty($weight))
        {
            header("Location: ../views/police.blade.php?error=the weight field is empty");
        }
        else if(empty($height))
        {
            header("Location: ../views/police.blade.php?error=the height field is empty");
        }
        else if(empty($image))
        {
            header("Location: ../views/police.blade.php?error=the image field id empty");
        }
        else
        {
            //image directory
            $target_dir = "uploads/";
            $target_file = $target_dir . basename($_FILES["image"]["name"]);

            //sending the details to the db
            try
            {
                $stmt = $conn->prepare("INSERT INTO criminals (criminal_name,crime_type,about_criminal,height,weight,criminal_photo) VALUES(:criminal_name,:crime_type,:about_criminal,:height,:weight,:criminal_photo)");
                $stmt->bindParam(":criminal_name",$criminalname);
                $stmt->bindParam(":crime_type",$crimetype);
                $stmt->bindParam(":about_criminal",$aboutcrime);
                $stmt->bindParam(":height",$height);
                $stmt->bindParam(":weight",$weight);
                $stmt->bindParam(":criminal_photo",$image);
                $rt = $stmt->execute();

                if($rt > 0)
                {
                    if (move_uploaded_file($_FILES['image']['tmp_name'], $target_file))
                    {
                        header("Location: ../views/police.blade.php?success");
                    }
                    else
                    {
                        header("Location: ../views/police.blade.php?error=the image failed to upload");
                    }
                }
            }
            catch(PDOException $e)
            {
                echo $e->getMessage();
            }
        }
    }
}
else
{
    header("Location: /index.php?error=unauthorised page request please login to access page");
}