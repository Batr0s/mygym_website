<?php
session_start();
require("../model/database.php");
$con = conectar();
echo "<link rel='stylesheet' type='text/css' href='../css/style-admin.css'>";
if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 0 || $_SESSION['type'] === NULL){
	header('location: ../view/index.html');
	}

if(isset($_POST['crea_clase'])){ 
	$nombre_clase = $_POST['name'];
    $id_instructor = $_POST['id_instructor'];

	crear_clase($con, $id_instructor, $nombre_clase);
	header("Location: ../view/admin.php");
}else{
		echo "
		<link rel='preconnect' href='https://fonts.googleapis.com' />
		<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin />
		
		<link
		  href='https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Raleway:wght@400;700;900&display=swap'
		  rel='stylesheet'
		/>
		<h1 style='text-align:center'>Crea una Clase</h1>	
		<div id='contenedor-form'>
			<div id='contenedor-form_1'>
				<fieldset>
					<legend>Crear la clase</legend>
						<div id='cont-form_1' >			
							<form method='post' action='".$_SERVER['PHP_SELF']."'>
								<label for='nombre'>Nombre de la Clase:</label><br>
									<input type='text' name='name' value=''/>
								<br><br>
								<label for='id_instructor'>Instructor:</label><br>
								<select name='id_instructor'>
									<option value=''>Seleccione...</option>";
								$resultado = obtener_instructores($con);
								while($linea = obtener_resultados($resultado)){
									extract($linea);
									echo "<option value='".$id."'>".$name . " " . $surname ."</option>";
								}    
						echo    "</select><br><br>
								<a class='btn ' href='../view/admin.php'>Atrás</a>
								<input class='btn' type='submit' name='crea_clase' value='Crear Clase'>
								<a class='btn' href='logout.php'>Logout</a>
							</form>";
				echo "</div>";
		echo   "</fieldset>";
	echo   "</div>";
echo "</div>";
}
cerrar_conexion($con);
?>