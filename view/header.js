let fijar = false;

function detectarScroll() {
  const contenedorNavegacion = document.querySelector('.contenedor-navegacion');
  const main = document.querySelector('main');
  const posicionMain = main.getBoundingClientRect();

  const posicionScroll = window.scrollY;
  const posicionMainTop = posicionMain.top + posicionScroll;

  // Si el scroll está por debajo de la cabecera le agrega la clase 'fijo', si está por encima, elimina la clase 'fijo'
  if (posicionMainTop < posicionScroll && fijar == false) {
    contenedorNavegacion.classList.add('fijo');
    fijar = true;
  } else if (posicionMainTop > posicionScroll && fijar == true) {
    contenedorNavegacion.classList.remove('fijo');
    fijar = false;
  }
}

window.addEventListener('scroll', detectarScroll);
