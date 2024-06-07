<?php
session_start();
require("../model/database.php");
$con = conectar();
echo "<link rel='stylesheet' type='text/css' href='../css/style-admin.css'>";
if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 0 || $_SESSION['type'] === NULL){
	header('location: ../view/index.html');
	}

if(isset($_POST['modificar'])){ 
	$nombre = $_POST['nombre'];
    $apellido = $_POST['apellido'];
	$fecha_nac = $_POST['fecha_nac'];
	$pass = $_POST['pass'];
    $email = $_POST['email'];
	$telefono = $_POST['telefono'];
	$tipo = $_POST['tipo'];
	modificar_user($con, $_SESSION["id_usuario"], $nombre, $apellido, $fecha_nac, $pass, $email, $telefono, $tipo);
	header("Location: ../view/admin.php");
}else{
	$id_usuario = $_GET["id"];
	$_SESSION["id_usuario"] = $id_usuario;
	$resultado = obtener_usuario($con, $_SESSION["id_usuario"]);
	$num_filas = obtener_num_filas($resultado);
	if($num_filas==0){
		header("Location: ../view/admin.php");
	}
	else{
		$datos_user = obtener_resultados($resultado);
		extract($datos_user);
		//echo $_SESSION["id_usuario"];
		echo "	<link rel='preconnect' href='https://fonts.googleapis.com' />
		<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin />
		
		<link
		  href='https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Raleway:wght@400;700;900&display=swap'
		  rel='stylesheet'
		/>";
		echo "
		<h1 style='text-align:center'>Modifica al usuario</h1>
		<div id='contenedor-form'>
    		<div id='contenedor-form_1'>
			<fieldset>
				<legend>Modifica al usuario</legend>
					<div id='cont-form_1' >
						<form method='post' action='".$_SERVER['PHP_SELF']."'>
							<label for='nombre'>Nombre usuario:</label><br>
								<input type='text' name='nombre' value='".$name."'/><br><br>
							<label for='apellido'>Apellido:</label><br>
								<input type='text' name='apellido' value='".$surname."'/><br><br>
							<label for='fecha_nac'>Fecha de nacimiento:</label><br>
								<input type='date' name='fecha_nac' value='".$fecha_nacimiento."'/><br><br>
							<label for='pass'>Contraseña:</label><br>
								<input type='password' name='pass' value='".$password."'><br><br>
							<label for='email'>Email:</label><br>
								<input type='email' name='email' value='".$email."'><br><br>
							<label for='text'>Telefono:</label><br>
								<input type='text' name='telefono' value='".$telefono."'><br><br>
							<label for='tipo'>Tipo:</label><br>
							<select name='tipo' id='add_tipo'>
								<option value='0'>Admin</option>
								<option value='1'>Normal</option>
							</select>
							<br><br>
							<a class='btn ' href='../view/admin.php'>Atrás</a>
							<input class='btn' type='submit' name='modificar' value='modificar'>
							<a class='btn' href='logout.php'>Logout</a>
							</form>";
				echo "";
				echo	"</div>
				</fieldset>
			</div>";
		echo "
		</div>";
	}
}
cerrar_conexion($con);
?>