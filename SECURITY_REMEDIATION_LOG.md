# Registro de reparación de seguridad

## Información general

- Repositorio: GersioTalrevez/panel
- Fecha: 2026-10-01
- Rama propuesta: security/remove-secrets-and-auth-bypass
- Alcance inicial: index.html, panel.html

## Resumen ejecutivo

Se detectó un problema crítico de seguridad: la autenticación del panel depende de valores almacenados en localStorage/sessionStorage y hay credenciales hardcodeadas en el frontend. Esto permite un bypass simple y expone información sensible.

## Hallazgos

### 1) Credenciales expuestas en el frontend
- Se detectan claves y emails hardcodeados en index.html y panel.html.
- Riesgo: exposición total en el navegador y código fuente.
- Corrección: eliminarlas del frontend y mover la validación a Supabase Auth o backend.

### 2) Bypass por localStorage / sessionStorage
- El acceso se permite si localStorage.getItem('admin_autenticado') === 'true'
- Riesgo: el usuario puede manipularlo desde consola y entrar sin autenticar.
- Corrección: eliminar todas estas banderas de autorización del navegador.

### 3) Operaciones sensibles con cliente de Supabase
- Se usa el cliente en el navegador para consultar y borrar datos de la tabla galeria.
- Riesgo: si RLS no está bien configurado, cualquiera puede consultar o borrar registros.
- Corrección: activar RLS, bloquear permisos anónimos y mover operaciones sensibles a backend/server.

### 4) XSS por renderizado inseguro
- Se usa innerHTML para insertar datos de la BD.
- Riesgo: ejecución de scripts si algún valor contiene HTML/JS.
- Corrección: crear nodos con createElement y textContent; sanitizar entradas.

### 5) Contraseñas mostradas y almacenadas
- Las contraseñas se muestran y se guardan en almacenamiento local.
- Riesgo: fuga de credenciales.
- Corrección: no guardar ni mostrar contraseñas en frontend.

## Plan de reparación

1. Eliminar claves y credenciales hardcodeadas.
2. Quitar la validación basada en localStorage/sessionStorage.
3. Configurar Supabase Auth real y RLS.
4. Revisar y limitar acceso a la tabla galeria.
5. Eliminar innerHTML con datos de usuario.
6. Añadir CSP y encabezados de seguridad.
7. Probar bypass, XSS y acceso no autorizado.

## Estado

Pendiente de implementación en la rama de seguridad.

