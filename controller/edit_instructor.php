<?php
session_start();
require("../model/database.php");
$con = conectar();
echo "<link rel='stylesheet' type='text/css' href='../css/style-admin.css'>";
if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 0 || $_SESSION['type'] === NULL){
	header('location: ../view/index.html');
	}

if(isset($_POST['modificar'])){ 
    $dni = $_POST['dni'];
    $nombre = $_POST['name'];
    $apellido = $_POST['surname'];
    $email = $_POST['email'];

	modificar_instructor($con, $_SESSION["id_instructor"], $dni, $nombre, $apellido, $email);
	header("Location: ../view/admin.php");
}else{
	$id_instructor = $_GET["id"];
	$_SESSION["id_instructor"] = $id_instructor;
	$resultado = obtener_instructor($con, $_SESSION["id_instructor"]);
	$num_filas = obtener_num_filas($resultado);
	if($num_filas==0){
		header("Location: ../view/admin.php");
	}
	else{
		$datos_instructor = obtener_resultados($resultado);
		extract($datos_instructor);
		//echo $_SESSION["id_usuario"];
		echo "
		<link rel='preconnect' href='https://fonts.googleapis.com' />
		<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin />
		
		<link
		  href='https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Raleway:wght@400;700;900&display=swap'
		  rel='stylesheet'
		/>
		<h1 style='text-align:center'>Modificar al instructor</h1>
		<div id='contenedor-form'>
			<div id='contenedor-form_1'>
			<fieldset>
				<legend>Realizar la modificación</legend>
					<div id='cont-form_1' >
						<form method='post' action='".$_SERVER['PHP_SELF']."'>
							<label for='dni'>DNI instructor:</label>
								<input type='text' name='dni' value='".$dni."'/><br>
							<label for='name'>Nombre:</label>
								<input type='text' name='name' value='".$name."'/><br>
							<label for='surname'>Apellido:</label>
								<input type='text' name='surname' value='".$surname."'/><br>			
							<label for='email'>Email:</label>
							<input type='email' name='email' value='".$email."'><br>
							<br><br>
							<a class='btn' href='../view/admin.php'>Atrás</a>
							<input class='btn' type='submit' name='modificar' value='modificar'>
							<a class='btn' href='logout.php'>Logout</a>
						</form>";
				echo "</div>";
		echo "</fieldset>";
	echo "</div>";
echo "</div>";	
	}
}
cerrar_conexion($con);
?>