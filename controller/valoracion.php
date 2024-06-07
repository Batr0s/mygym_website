<?php
require("../model/database.php");
	$con = conectar();
	if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 1 ||  $_SESSION['type'] === NULL){
		header('location: ../view/index.html');
	}

//
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
   
    $data = json_decode(file_get_contents('php://input'), true);
    $id_clase = $data['clase'];
    $valor = $data['valoracion'];
    
    //var_dump($_POST);
    inserta_valoracion($con, $valor, $id_clase);
    seleccionGrupo($con);
    actualizarTablaClases($con);    
}else {
    echo "Error al enviar el formulario. Intentelo mas tarde.";
}
cerrar_conexion($con);
?>