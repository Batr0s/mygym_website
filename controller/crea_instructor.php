<?php
session_start();
require("../model/database.php");
$con = conectar();
echo "<link rel='stylesheet' type='text/css' href='../css/style-admin.css'>";
if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 0 || $_SESSION['type'] === NULL){
	header('location: ../view/index.html');
	}

if(isset($_POST['crea_instructor'])){ 
	$dni = $_POST['dni'];
    $nombre_instructor = $_POST['name'];
    $surname = $_POST['surname'];
    $email = $_POST['email'];
    

	crear_instructor($con, $dni, $nombre_instructor, $surname, $email);
	header("Location: ../view/admin.php");
}else{
		echo "	<link rel='preconnect' href='https://fonts.googleapis.com' />
		<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin />
		
		<link
		  href='https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Raleway:wght@400;700;900&display=swap'
		  rel='stylesheet'
		/>";
		echo "	
		<h1 style='text-align:center'>Añade nuevos instructores</h1>
		<div id='contenedor-form'>
    		<div id='contenedor-form_1'>
			<fieldset>
				<legend>Realizar Alta</legend>
					<div id='cont-form_1' >
						<form method='post' action='".$_SERVER['PHP_SELF']."'>
							<label for='name'>Nombre del instructor:</label><br>
								<input type='text' name='name' value=''/><br><br>
						
							<label for='surname'>Apellido:</label><br>
								<input type='text' name='surname' value=''/><br><br>
						
							<label for='dni'>DNI:</label><br>
								<input type='text' name='dni' value=''/><br><br>
						
							<label for='email'>Email:</label><br>
								<input type='email' name='email' value=''/><br><br>
								<a class='btn ' href='../view/admin.php'>Atrás</a>
							<input class='btn' type='submit' name='crea_instructor' value='Dar Alta'>
							<a class='btn ' href='logout.php'>Logout</a>
						</form>";
						echo "";
				echo "";
			echo	"</div>
				</fieldset>
			</div>";
		echo "
		</div>";
}
cerrar_conexion($con);
?>