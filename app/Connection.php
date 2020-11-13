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
}
catch(PDOException $e)
{
    echo "failed to establish a connection with the database. server might be off";
}