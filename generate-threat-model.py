from pytm import TM, Actor, Process, Dataflow, Boundary
from pytm.pytm import Action
import os
import json

# Rutas de los archivos
GV_FILE_PATH = "/home/mj/Documents/Environments/pytm/Documentos/Flujo de datos/Inglés/flujo_datos_diagrama_inglés.gv"
OUTPUT_FILE_PATH = "/home/mj/Documents/Environments/pytm/Documentos/Evidencias/threat_model.json"
TEMPLATE_PATH = "/home/mj/Documents/Environments/pytm/lib/python3.12/site-packages/pytm/templates/dfd.html"

# Verifica si la plantilla existe
if not os.path.exists(TEMPLATE_PATH):
    raise FileNotFoundError(f"La plantilla no se encontró en {TEMPLATE_PATH}")

def convert_sets_to_lists(data):
    """
    Recorre un objeto (puede ser un diccionario, lista, o conjunto)
    y convierte todos los conjuntos (set) en listas.
    """
    if isinstance(data, set):
        return list(data)
    elif isinstance(data, dict):
        return {key: convert_sets_to_lists(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_sets_to_lists(item) for item in data]
    else:
        return data

def gv_to_pytm(file_path):
    # Crear el modelo de amenazas
    tm = TM("Threat Model from GV")
    tm.description = "Modelo de amenazas generado desde un archivo .gv con pytm"
    tm.assumptions = "Este modelo asume que los datos están en un entorno seguro."
    tm.onDuplicates = Action.IGNORE

    # Agregar componentes al modelo
    tm.actors = [
        Actor(name="User", description="Un usuario interactuando con el sistema.")
    ]
    tm.processes = [
        Process(name="Web Application", description="Procesa solicitudes del usuario.")
    ]
    tm.dataflows = [
        Dataflow(
            tm.actors[0],
            tm.processes[0],
            name="User to WebApp",
            description="Flujo de datos del usuario a la aplicación."
        )
    ]
    tm.boundaries = [
        Boundary(name="Trust Boundary", description="Límite entre el usuario y la aplicación.")
    ]

    # Generar el informe
    try:
        print("Generando el informe del modelo...")
        tm.report(template_path=TEMPLATE_PATH)
        print("Informe generado exitosamente.")
    except Exception as e:
        print(f"Error al generar el informe: {e}")

    # Exportar el modelo a JSON
    try:
        print(f"Exportando el modelo a {OUTPUT_FILE_PATH}...")
        model_data = {
            "name": tm.name,
            "description": tm.description,
            "assumptions": tm.assumptions,
            "actors": [{"name": actor.name, "description": actor.description} for actor in tm.actors],
            "processes": [{"name": process.name, "description": process.description} for process in tm.processes],
            "dataflows": [
                {"name": flow.name, "description": flow.description} for flow in tm.dataflows
            ],
            "boundaries": [{"name": boundary.name, "description": boundary.description} for boundary in tm.boundaries],
            "findings": tm.findings,  # Findings pueden contener sets
        }

        # Convertir todos los sets a listas en el modelo
        model_data_cleaned = convert_sets_to_lists(model_data)

        with open(OUTPUT_FILE_PATH, "w") as output_file:
            json.dump(model_data_cleaned, output_file, indent=4)
        print("Modelo exportado correctamente.")
    except Exception as e:
        print(f"Error al exportar el modelo: {e}")

if __name__ == "__main__":
    gv_to_pytm(GV_FILE_PATH)