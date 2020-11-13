<?php

session_start();

if(isset($_SESSION['auth']))
{
    session_unset();
    session_destroy();
    if(!isset($_SESSION['auth']))
    {
        header("Location: /index.php");
    }
}
else
{
    header("Location: /index.php?error=you need to be logged in ");
    exit;
}