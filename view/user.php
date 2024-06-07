<?php
session_start();
	require("../model/database.php");
	$con = conectar();
	if (!isset($_SESSION['nombre_user']) || $_SESSION['type'] != 1 ||  $_SESSION['type'] === NULL){
		header('location: ../view/index.html');
	}

?>

<!DOCTYPE html>
<html lang="es">
   <head>
    <meta charset="UTF-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login - VitalWay Gym</title>
    
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    
    <link
      href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700&family=Raleway:wght@400;700;900&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="../css/style-user.css" />
    <script src="valoracion.js" defer></script>
  </head>
  <body>
    <header>
      <h1 class="nombre-sitio">VitalWay <span> Gym </span></h1>

	  <h2>Bienvenido <?php echo $_SESSION['nombre_user'];?></h2>
    </header>

    <div class="contenedor-navegacion">
      <nav class="nav-principal contenedor">
        <a href="index.html">Inicio</a>
      </nav>
    </div>

    <main class="contenido-principal contenedor">
     

      <form class="form-reserva" id="form"  method = "POST"> <!-- Se añade el action y metodo para ejecutar la validació del server -->
	  <fieldset>
          <legend>Realizar Reserva</legend>

          <div class="campo">
           Clase: 
            <select name="clase">
			<?php 
	    $clases= obtener_clases($con);
		while($fila = obtener_resultados($clases)){
			extract($fila);
			echo "<option value='$id'>$name</option>";
			
			
		}
		?>
		</select>
          </div>

          <div class="campo">
           
		   Fecha:
			<input name="fecha" type="date">
          </div>
         
        </fieldset>

        <button  class="btn" name="reservar"> RESERVAR </button>

      </form>
      
      <h3>Reservas realizadas:</h3>
      <?php
    $reservas = obtener_reserva_user($con, $_SESSION['id_user']);
    if (mysqli_num_rows($reservas) > 0){
      while ($fila = obtener_resultados($reservas)) {
        // Mostrar información de reserva
        echo "<p>Nombre de usuario: " . $_SESSION['nombre_user'] . "</p>";
        echo "<p>Nombre de clase: " . $fila['nombre_clase'] . "</p>";
        echo "<p>Fecha: " . date("Y-m-d", strtotime($fila['date'])). "</p>";
        // Formulario para eliminar reserva
        echo "<form class='eliminar' method='POST'>";
        echo "<input type='hidden' name='reserva_id' value='" . $fila['id'] . "'>";
        echo "<button class='btn eliminar' name='eliminar_reserva'>Eliminar reserva</button>";
        echo "</form>";
      }
    } else {
      echo "Aún no tienes reservas realizadas";
    }
    ?>
  <div class="valor-container">
    <fieldset class="valor">
      <legend>Dejanos tu valoración</legend>
      <form id="formulario-valoracion">
        <div class="campo">
          Clase: 
          <select name="clase" id="clase">
            <?php 
                  $clases= obtener_clases($con);
                  while($fila = obtener_resultados($clases)){
                    extract($fila);
                    echo "<option value='$id'>$name</option>";   
                  }
                  ?>
              </select>
        </div>
            <div id="input-valoracion" class="radio-input">
              <input value="5" name="value-radio" id="value-1" type="radio" class="star s1"
              />
              <input value="4" name="value-radio" id="value-2" type="radio" class="star s2"
              />
              <input value="3" name="value-radio" id="value-3" type="radio" class="star s3"
              />
              <input value="2" name="value-radio" id="value-4" type="radio" class="star s4"
              />
              <input value="1" name="value-radio" id="value-5" type="radio" class="star s5"
              />
            </div>
          </fieldset>
          <div id="mensaje"></div>
          <!-- <div id="cerrar_sesion"> -->
            <button class="btn" type="submit">Enviar</button>
            <button class="btn"><a href="../controller/logout.php">Logout</a></button>
          <!-- </div> -->
      </form>
  </div>
    </main> 
    
    
    <?php

if(isset($_POST["reservar"])){
  
  $date=$_POST["fecha"];
  $currentDate= date("Y-m-d");
  $fecha_timestamp = strtotime($date);
  $fecha_actual = strtotime($currentDate);
  
  if($fecha_timestamp<$fecha_actual){
    echo "La fecha ingresada no es correcta </br>";
  }
  
  $class_id=$_POST["clase"];
		$user_id=$_SESSION["id_user"];


	if(!empty($_POST["fecha"]) && !empty($_POST["clase"]) && $fecha_timestamp>$fecha_actual){  

          crear_reserva($con,$user_id, $class_id, $date);

		  echo "Reserva realizada correctamente";
      header("location: user.php");

	}else{ echo "Los datos no son correctos"; }
         
		}

    
    if(isset($_POST["eliminar_reserva"])){

     
        $reservasEliminar=$_POST["reserva_id"];
        eliminar_reserva($con, $reservasEliminar);
        header("location: user.php");
    
    }



		?>

    <footer class="site-footer">
        <div>
          <h3>Contacto</h3>
          <p><span>Ubicación:</span>C/ de Balmes, 32, Barcelona</p>
          <p><span>Teléfono: </span> 97233568</p>
          <p><span>Mail:</span>vitalway@gmail.com</p>
        </div>
  
        <p class="copyright"> &#169 Todos los derechos Reservados, VitalWay</p>
      </footer>
  </body>
</html>

