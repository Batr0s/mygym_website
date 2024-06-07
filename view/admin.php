<?php
session_start();
	require("../model/database.php");
	$con = conectar();
	/* var_dump($_SESSION['type']); */
	if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 0 ||  $_SESSION['type'] === NULL){
		header('location: ../view/index.html');
	}

?>
<!DOCTYPE html>
<html>
<head lang="es">
    <meta charset="UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge" />
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" type="text/css" href="../css/style-admin.css">
    <title>Administración</title>
	<link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    
    <link
      href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Raleway:wght@400;700;900&display=swap"
      rel="stylesheet"
    />
    <!-- <link rel="stylesheet" href="../css/style-user.css" /> -->
	<!-- <link rel="stylesheet" href="../css/style.css" /> -->
</head>
<body>
    <h1 style="text-align:center">Bienvenido a la administración <?php echo $_SESSION['nombre_user'];?>!</h1>
	<div class="contenedor">
    	<div id="contenedor_1">
		<div id="form_1">
			<h2 class="text-center">Gestión de usuarios</h2>
				<form method='post' action='../controller/elimina_user.php'>
					<table border="5px outset #c2c2c2">
						<tr>
							<th>ID</th>
							<th>Nombre</th>
							<th>Apellido</th>
							<th>Fecha de nacimiento</th>
							<th>Contraseña</th>
							<th>Email</th>
							<th>Telefono</th>
							<th>Tipo</th>
							<th>Editar</th>
							<th>Eliminar</th>
						</tr>
						<?php
						//$resultado = obtener_usuarios($con);
						$datos_user = obtener_usuarios($con);
						$num_filas = obtener_num_filas($datos_user);
						$mensaje = "";
						if($num_filas == 0){
							$mensaje = "<p>No hay usuarios dados de alta.</p>";
						}
						while ($linea = obtener_resultados($datos_user)) {							
							extract($linea);
								
								echo "<tr class='linea efecto1'>";
								echo "<td>".$id."</td>";
								echo "<td>".$name."</td>";
								echo "<td>".$surname."</td>";
								echo "<td>".$fecha_nacimiento."</td>";
								echo "<td>".$password."</td>";
								echo "<td>".$email."</td>";
								echo "<td>".$telefono."</td>";
								echo "<td>".$type."</td>";

								echo "<td><a href='../controller/edit_user.php?id=$id'>Editar</a></td>";
								echo "<td style='text-align:center'><input type='checkbox' name='borrar[]' value='".$id."'></td>";
								echo "</tr>";
						}
					
					echo "<tr class='linea'><td colspan='9'>".$mensaje."</td><td colspan='10' style='text-align:center'><input class='btn' type='submit' value='Borrar'/></td></tr>";
					?>
					</table>
				</form>
		</div>
		<div id="form_2">
			<h2 class="text-center">Gestión de instructores</h2>
				<form method='post' action='../controller/elimina_instructor.php'>
					<table border="5px outset #c2c2c2">
						<tr>
							<th>ID</th>
							<th>Nombre</th>
							<th>Apellido</th>
							<th>Email</th>
							<th>Editar</th>
							<th>Eliminar</th>
							<th>Dar de alta instructor</th>
						</tr>
						<?php
						$datos_instructor = obtener_instructores($con);
						$num_filas = obtener_num_filas($datos_instructor);
						$mensaje = "";
						if($num_filas == 0){
							$mensaje = "<p>No hay usuarios dados de alta.</p>";
						}
						while ($linea = obtener_resultados($datos_instructor)) {							
							extract($linea);
								
								echo "<tr class='linea efecto1'>";
								echo "<td>".$id."</td>";
								echo "<td>".$name."</td>";
								echo "<td>".$surname."</td>";
								echo "<td>".$email."</td>";
								
								echo "<td><a href='../controller/edit_instructor.php?id=$id'>Editar</a></td>";
								echo "<td style='text-align:center'><input type='checkbox' name='borrar[]' value='".$id."'></td>";
								echo "<td></td>";
								echo "</tr>";
						}
					
					echo "<tr class='linea'><td colspan='5'>".$mensaje."</td><td colspan='1' style='text-align:center'><input class='btn' type='submit' value='Borrar'/></td>
					<td colspan='1'><a class='btn' href='../controller/crea_instructor.php'>Dar Alta</a></td>
					</tr>";
					?>
					</table>
				</form>
		</div>
		</div>
		<div id="contenedor_2">
		<div id="form_3">
			<h2 class="text-center">Gestión de Clases</h2>
				<form method='post' action='../controller/elimina_clase.php'>
					<table border="5px outset #c2c2c2">
						<tr>
							<th>ID Clase</th>
							<th>ID Instructor</th>
							<th>Nombre Clase</th>
							<th>Editar</th>
							<th>Eliminar</th>
							<th>Crear nueva Clase</th>
						</tr>
						<?php
						$datos_clase = obtener_clases($con);
						$num_filas = obtener_num_filas($datos_clase);
						$mensaje = "";
						if($num_filas == 0){
							$mensaje = "<p>No hay usuarios dados de alta.</p>";
						}
						while ($linea = obtener_resultados($datos_clase)) {							
							extract($linea);
								
								echo "<tr class='linea efecto1'>";
								echo "<td>".$id."</td>";
								echo "<td>".$instructor_id."</td>";
								echo "<td>".$name."</td>";
								
								echo "<td><a href='../controller/edit_clase.php?id=$id'>Editar</a></td>";
								echo "<td style='text-align:center'><input type='checkbox' name='borrar[]' value='".$id."'></td>";
								echo "<td></td>";
								echo "</tr>";
						}
						
					echo "<tr class='linea'><td colspan='4'>".$mensaje."</td><td colspan='1' style='text-align:center'><input class='btn' type='submit' value='Borrar'/></td>
					<td colspan='1'><a class='btn' href='../controller/crea_clase.php'>Añadir</a></td>
					</tr>";
					?>
					<!-- <td colspan='1'><a href='../controller/crea_clase.php'>Añadir</a></td> -->
					</table>
				</form>
		</div>
		
		<div id="form_4">
			<a class='btn' href="../controller/logout.php">Logout</a>
		</div>
		</div>
	</div>
</body>
</html>
<?
cerrar_conexion($cons);
?>