<?php
require_once 'db.php';
require_once 'auth.php';

$auth = new Auth($conn);
$auth->logout();

header('Location: login.php?message=logged_out');
exit;
