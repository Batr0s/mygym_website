<?php
$host = "localhost";
$user = "root";
$pass = "root";
$db_name = "my_gym";

function conectar(){
	$con = mysqli_connect($GLOBALS["host"], $GLOBALS["user"], $GLOBALS["pass"]) or die("Error al conectar con la base de datos");
	//crear_bdd($con);
	mysqli_select_db($con, $GLOBALS["db_name"]);
	return $con;
}
/*Funciones usuarios */
function obtener_usuarios($con){
	$consulta = mysqli_query($con, "select * from users");
	return $consulta;
}

function obtener_usuario($con, $id_usuario){
	$consulta = $con->prepare("select * from users where id = ? ");
	$consulta->bind_param('i', $id_usuario);
	$consulta->execute();
	$resultado = $consulta->get_result(); 
	return $resultado;
}

function valida_usuario($con, $email, $pass){
	$consulta = $con->prepare("select * from users where email = ? and  password = ?;");
	$consulta->bind_param("ss", $email, $pass);
	$consulta->execute();
	$resultado = $consulta->get_result(); 
	return $resultado;
}
/*-------*/
function obtener_num_filas($consulta){
	return mysqli_num_rows($consulta);
}

function obtener_resultados($resultado){
	return mysqli_fetch_array($resultado);
}
/*------*/
/*Se agrego los parametros de fecha_nac y telefono */
function crear_usuario($con, $nombre, $apellido, $fecha_nac, $pass, $email, $telefono, $tarifa, $tipo){
    $stmt = $con->prepare("INSERT INTO users (name, surname, fecha_nacimiento, password, email, telefono, tarifa, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssssssi", $nombre, $apellido, $fecha_nac, $pass, $email, $telefono, $tarifa, $tipo);
    $stmt->execute();
    $stmt->close();
}

function elimina_user($con, $identificadores){
	$consulta = "delete from users where id in (";
	foreach($identificadores as $indentificador){
		$consulta = $consulta.$indentificador.", ";
	}
	$consulta = $consulta."0)";
	mysqli_query($con, $consulta);
}

function modificar_user($con, $id, $nombre, $apellido, $fecha_nac, $pass, $email, $telefono, $tipo){
	$consulta = $con->prepare("update users set name=?, surname=?, fecha_nacimiento=?, password=?, email=?, telefono=?, type=? where users.id=?");
	$consulta->bind_param("ssssssii", $nombre, $apellido,$fecha_nac, $pass, $email, $telefono, $tipo, $id);
	$consulta->execute();
	$consulta->close();
}
/**Consultas instructores */
function obtener_instructores($con){
	$consulta = mysqli_query($con, "select * from instructor");
	return $consulta;
}

function obtener_instructor($con, $id){
	$consulta = $con->prepare("select * from instructor where id =?");
	$consulta->bind_param('i', $id);
	$consulta->execute();
	$resultado = $consulta->get_result();
	$consulta->close();
	return $resultado; 
}

function crear_instructor($con, $dni, $name, $surname, $email){
    $stmt = $con->prepare("INSERT INTO instructor (dni, name, surname, email) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $dni, $name, $surname, $email);
    $stmt->execute();
    $stmt->close();
}

function elimina_instructor($con, $identificadores){
	$consulta = "delete from instructor where id in (";
	foreach($identificadores as $indentificador){
		$consulta = $consulta.$indentificador.", ";
	}
	$consulta = $consulta."0)";
	mysqli_query($con, $consulta);
}

function modificar_instructor($con, $id, $dni, $name, $surname, $email){
    $consulta = $con->prepare("update instructor SET dni=?, name=?, surname=?, email=? where id=?");
    $consulta->bind_param("ssssi", $dni, $name, $surname, $email, $id);
    $consulta->execute();
	$consulta->close();
}
/**Consultas Clases */
function obtener_clases($con){
	$consulta = mysqli_query($con, "select * from classes");
	return $consulta;
}

function obtener_clase($con, $id){
	$consulta = $con->prepare("select * from classes where id =?");
	$consulta->bind_param('i', $id);
	$consulta->execute();
	$resultado = $consulta->get_result();
	$consulta->close();
	return $resultado; 
}

function crear_clase($con, $id_instructor, $name){
    $stmt = $con->prepare("INSERT INTO classes (instructor_id, name) VALUES (?,?)");
    $stmt->bind_param("is", $id_instructor, $name);
    $stmt->execute();
    $stmt->close();
}

function elimina_clase($con, $identificadores){
	$consulta = "delete from classes where id in (";
	foreach($identificadores as $indentificador){
		$consulta = $consulta.$indentificador.", ";
	}
	$consulta = $consulta."0)";
	mysqli_query($con, $consulta);
}

function modificar_clase($con, $id, $name){
    $consulta = $con->prepare("update classes SET name=? where id=?");
    $consulta->bind_param("si",$name, $id);
    $consulta->execute();
	$consulta->close();
}

/*Consultas reservas */

function obtener_reservas($con){
	$consulta = mysqli_query($con, "select * from reserves;");
	return $consulta; 
}

function obtener_reserva_user($con, $user_id){
	$resultadoReservaUser= mysqli_query($con, "select r.id, r.user_id, r.class_id, r.date, c.name AS nombre_clase
	FROM reserves AS r
	JOIN classes AS c ON r.class_id = c.id
	WHERE r.user_id = $user_id;");
	return $resultadoReservaUser;
}

function crear_reserva($con, $user_id, $class_id, $date){
	$stmt = $con->prepare("INSERT INTO reserves (user_id, class_id, date) VALUES (?, ?, ?)");
    $stmt->bind_param("iis", $user_id, $class_id, $date);
    $stmt->execute();
    $stmt->close();
}

function eliminar_reserva($con, $id_eliminar){
	$consulta = "delete from reserves where id=$id_eliminar";
	
	/*"delete from reserves where id in (";
	foreach($identificadores as $indentificador){
		$consulta = $consulta.$indentificador.", ";
	}
	$consulta = $consulta."0)"; */
	mysqli_query($con, $consulta);
}

function comprobar_email($con, $email){
	$resultado = mysqli_query($con, "select * from users where email ='".$email."'");
	$resultado = obtener_resultados($resultado);
	if ($resultado === null) {
		throw new Exception("El email no se encuentra en nuestro sistema.");
	}
	return ($resultado["name"]);
}

function crear_token($con, $token, $caducidad, $email) {
    $stmt = $con->prepare("INSERT INTO password_tokens (token, fecha_caducidad, email) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $token, $caducidad, $email);
    $stmt->execute();
    $stmt->close();
}

function comprobar_token($con, $token) {
	$resultado = mysqli_query($con, "select * from password_tokens where token ='".$token."'");
	$resultado = obtener_resultados($resultado);

	if ($resultado === null) {
		throw new Exception("No tienes permiso para esa acción.");
	}
	$fecha_actual = time();
	$fecha_actual = strtotime(date('Y-m-d H:i:s', $fecha_actual));
	$fecha_caducidad = strtotime($resultado["fecha_caducidad"]);
	if (($fecha_caducidad - $fecha_actual) < 0) {
		throw new Exception("Enlace caducado, vuelva a solicitar el cambio de contraseña.");
	}
	return ($resultado["email"]);
}

function cambiar_password($con, $email, $pass) {
	$consulta = "update users set password='".$pass."' where email='".$email."'";
	mysqli_query($con, $consulta);
}

/*Valoración */
function inserta_valoracion($con, $valor, $id_clase){
	$consulta = $con->prepare("insert into valoracion (valor, id_clase) values (?, ?)");
	$consulta->bind_param("ii", $valor, $id_clase);
	$consulta->execute();
	$consulta->close();
}

function seleccionGrupo($con){
	//Paso 1: Agrupa las valoraciones por clase y calcula la media
	function calcularMediaValoraciones($con) {
		$consulta = $con->prepare("SELECT v.id_clase,
			AVG(v.valor) AS valor_media_clase
			FROM Valoracion v
			GROUP BY v.id_clase");
		$consulta->execute();
		$resultado = $consulta->get_result();
		$consulta->close();
	}
}


function actualizarTablaClases($con) {
	//Paso 2: Actualiza la tabla de clases con la media de valoraciones
    $consulta = $con->prepare("UPDATE Classes c
        JOIN (
            SELECT v.id_clase,
			ROUND(AVG(v.valor), 1) AS valor_media_clase
                FROM Valoracion v
                GROUP BY v.id_clase
        ) subconsulta ON c.id = subconsulta.id_clase
        SET c.valor_media_clase = subconsulta.valor_media_clase");
    $consulta->execute();
    $consulta->close();
}

/** */

function cerrar_conexion($con){
	mysqli_close($con);
}

?>