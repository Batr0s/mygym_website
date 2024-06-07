document.getElementById("form").addEventListener("submit", function (event) {
  event.preventDefault(); // Evitar el envío del formulario por defecto

  const formData = new FormData(event.target);

  fetch("../controller/gestor.php", {
    method: "POST",
    body: formData,
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error("Ocurrió un error al enviar los datos.");
      }
      return response.text();
    })
    .then((data) => {
      if (data.includes("Usuario o contraseña incorrectos")) {
        document.getElementById("mensajeError").textContent =
          "Usuario o contraseña incorrectos.Vuelve a intentarlo.";
      } else {
        window.location.href = data;
      }
    })
    .catch((error) => {
      console.error("Error:", error);
    });
});
