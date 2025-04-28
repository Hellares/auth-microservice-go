-- Agregar columna DNI a la tabla users
ALTER TABLE users ADD COLUMN dni VARCHAR(20) UNIQUE NOT NULL;
 
-- Eliminar la columna email ya que no será necesaria
ALTER TABLE users DROP COLUMN email; 