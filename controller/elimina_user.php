<?php
session_start();
require("../model/database.php");
$con = conectar();
if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 0 || $_SESSION['type'] === NULL){
	header('location: ../view/index.html');
	}
$identificadores = $_POST["borrar"];
elimina_user($con, $identificadores);
cerrar_conexion($con);
header("location:../view/admin.php");
?>