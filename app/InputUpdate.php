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
    if(isset($_POST['update_status']))
    {
        $name = testInput($_POST['name']);
        $caseStatus = testInput($_POST['status']);

        //checking if the fields are empty or not
        if(empty($name))
        {
            header("Location: ../views/police.blade.php?error=the name field is empty please to fill it up");
        }
        else if(empty($caseStatus))
        {
            header("Location: ../views/police.blade.php?error=the status field is empty please to fill it up");
        }
        else
        {
            try
            {
                //checking if the user with the case name exists
                $stmt = $conn->prepare("SELECT id,user_name FROM report_crime WHERE id=?");
                $stmt->bindValue(1,$name);
                $stmt->execute();

                if($stmt->rowCount())
                {
                    while($data = $stmt->fetch(PDO::FETCH_ASSOC))
                    {
                        //getting this from the db
                        $caseId = $data['id'];
                        $casename = $data['user_name'];

                        //checking if the case id already exist in the database

                        $stmt = $conn->prepare("SELECT case_id FROM report_status WHERE case_id=?");
                        $stmt->bindValue(1,$name);
                        $rt = $stmt->execute();

                        if($rt > 0)
                        {
                            //sending the details to the database
                            $stmt = $conn->prepare("DELETE FROM report_status WHERE case_id=?");
                            $stmt->bindValue(1,$name);
                            $rt = $stmt->execute();

                            if($rt > 0)
                            {
                                $stmt = $conn->prepare("INSERT INTO report_status (user_name,case_id,case_status) VALUES(:user_name,:case_id,:case_status)");
                                $stmt->bindParam(":user_name",$casename);
                                $stmt->bindParam(":case_id",$caseId);
                                $stmt->bindParam(":case_status",$caseStatus);
                                $rt = $stmt->execute();

                                if($rt > 0)
                                {
                                    header("Location: /views/police.blade.php?success=status updated successfully");
                                }
                                else
                                {
                                    header("Location: /views/police.blade.php?error=status failed to update");
                                }
                            }
                        }
                        else
                        {
                            //sending the details to the database
                            $stmt = $conn->prepare("INSERT INTO report_status (user_name,case_id,case_status) VALUES(:user_name,:case_id,:case_status)");
                            $stmt->bindParam(":user_name",$casename);
                            $stmt->bindParam(":case_id",$caseId);
                            $stmt->bindParam(":case_status",$caseStatus);
                            $rt = $stmt->execute();

                            if($rt > 0)
                            {
                                header("Location: /views/police.blade.php?success=status updated successfully");
                            }
                            else
                            {
                                header("Location: /views/police.blade.php?error=status failed to update");
                            }
                        }
                        
                    }
                    
                }
                else
                {
                    header("Location: ../views/police.blade.php?error=the case of that id does not exist");
                }
    
            }
            catch(PDOException $e)
            {
                echo $e->getMessage();
            }
        }
    }
    else if(isset($_POST['report']))
    {
        $aboutcriminal = testInput($_POST['aboutcriminal']);
        $crimetype = testInput($_POST['crimetype']);

        //checking if the fields are filled up or not
        if(empty($aboutcriminal))
        {
            header("Location: ../views/report.blade.php?error=the about criminal field is empty");
        }
        else if(empty($crimetype))
        {
            header("Location: ../views/report.blade.php?error=the crime type field is empty");
        }
        else
        {
            $stmt = $conn->prepare("INSERT INTO report_crime (user_name,user_email,about_criminal,crime_type) VALUES(:user_name,:user_email,:about_criminal,:crime_type)");
            $stmt->bindParam(":user_name",$_SESSION['authName']);
            $stmt->bindParam(":user_email",$_SESSION['auth']);
            $stmt->bindParam(":about_criminal",$aboutcriminal);
            $stmt->bindParam(":crime_type",$crimetype);
            $rt = $stmt->execute();

            if($rt > 0)
            {
                header("Location: /views/report.blade.php?success=crime reported successfully");
            }
            else
            {
                header("Location: /views/report.blade.php?error=failed to submit crime");
            }
        }
    }
}
else
{
    header("Location: /index.php?error=unauthorised page request please login to access page");
}