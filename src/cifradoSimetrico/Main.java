package cifradoSimetrico;

/**
 * @author Alberto Mangut Bustamante y Juan Antonio Silva Luj�n
 * @version 1.0
 */
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.text.DecimalFormat;
import java.io.IOException;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;




/** 
 * Clase que permite invocar a los m�todos destinados al cifrado y descifrado de archivos as� como la modificaci�n del algoritmo de cifrado
 * por defecto. Se debe inicializar un objeto header y un bufferedReader para el correcto funcionamiento de la clase.
 */

public class Main {

	// Atributos de la clase MAIN

	static Header head = new Header();
	static BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

	
	
	/**
	   * Intenta cifrar el archivo que se introduce por argumentos generando una nueva semilla que se almacenar� en la cabecera
	   * junto con el algoritmo que ha sido seleccionado para el mismo. En caso de fallo en el almacenado de la cabecera se mostrar� un mensaje de error.
	   * Se pedir� al usuario que introduzca la contrase�a con la que desea cifrar el archivo. Una vez que se ha realizado el proceso de cifrado 
	   * se genera un archivo con el mismo nombre que el archivo introducido pero a�adiendole la extensi�n .cif. Adem�s mostrar� un mensaje
	   * informando del exito en el cifrado y el peso del archivo generado.   
	   * Si no se consigue cifrar exitosamente mostrar� un mensaje advirti�ndolo.
	   * @param archivo File con la ruta del archivo a descifrar.
	   */
	
	public static void cifrado(File archivo) {

		// Generaci�n de contrase�a
		System.out.print("Introducir contrase�a para el cifrado:  ");

		String pass;
		try {

			// Obtenemos la contrase�a para el cifrado del fichero.
			pass = br.readLine();
			char[] passw = pass.toCharArray();
			PBEKeySpec password = new PBEKeySpec(passw);

			// Generamos una nueva semilla y la almacenamos en la cabecera.
			byte[] seed = new byte[8];
			SecureRandom rand = new SecureRandom();
			rand.nextBytes(seed);
			// Almacenamos la nueva semilla en la cabecera.
			head.setSalt(seed);

			PBEParameterSpec pPS = new PBEParameterSpec(head.getSalt(), 64);

			// SecrectKeyFactory: Nos permitir� generar la clave de sesi�n para el algoritmo
			// elegido;
			// La crearemos indicando el algoritmo para el que se quiere la clave:
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(head.getAlgorithm());
			SecretKey secretKeyPass = keyFactory.generateSecret(password);

			// Cipher: Clase cifrador; la crearemos indicando el algoritmo
			// y despu�s la iniciaremos con la clave y los par�metros:
			Cipher cifrado = Cipher.getInstance(head.getAlgorithm());
			cifrado.init(Cipher.ENCRYPT_MODE, secretKeyPass, pPS);

			// Creamos el archivo de salida.

			OutputStream archivoCifrado = new FileOutputStream(archivo.getAbsolutePath() + ".cif");

			// Guardamos la cabecera en el fichero de salida.
			if (!head.save(archivoCifrado)) {
				System.out.println("Error al almacenar la cabecera en el archivo.");
			}

			// Creamos el fichero de entrada que se ha introducido por argumentos.
			FileInputStream entrada = new FileInputStream(archivo.getAbsolutePath());
			// Creamos el flujo de cifrado.
			CipherOutputStream ciflujout = new CipherOutputStream(archivoCifrado, cifrado);

			byte[] bloqueBytes = new byte[1024];
			int i;

			while ((i = entrada.read(bloqueBytes)) != -1) {

				ciflujout.write(bloqueBytes, 0, i);
				System.out.print(bloqueBytes.length + " .");
			}
			// Cerrado de flujos.
			entrada.close();
			ciflujout.close();
			archivoCifrado.close();

			DecimalFormat df = new DecimalFormat("#.00");
			float longitud = new File(archivo.getAbsolutePath() + ".cif").length();

			String peso = "";

			if (longitud > 1024000000)
				peso = (df.format(longitud / 1024000000) + " Gb");
			else if (longitud > 1024000)
				peso = (df.format(longitud / 1024000) + " Mb");
			else if (longitud > 1024)
				peso = (df.format(longitud / 1024) + " Kb");
			else
				peso = (df.format(longitud) + " bytes");

			System.out.println();
			System.out
					.println(" _____________________________________________________________________________________");
			System.out.println(
					"|  ARCHIVO " + archivo.getName() +   " CIFRADO CORRECTAMENTE" + "(" + peso +")");
			System.out
					.println("|_____________________________________________________________________________________");
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			System.out.println("Se ha producido un error durante el encriptado.");
			System.out.println("");
		}

	}
	
	/**
	   * Intenta descifrar el archivo que se introduce por argumentos haciendo uso de la cabecera que viene en el fichero
	   * y pidiendo la contrase�a con la que se cifr� el archivo. En caso de disponer de dicha contrase�a generar� un archivo descifrado
	   * con el mismo nombre que el archivo introducido pero a�adiendole la extensi�n .des. Adem�s mostrar� un mensaje informando del exito
	   * en el descifrado y el peso del archivo generado.   
	   * Si no se consigue descifrar exitosamente mostrar� un mensaje advirti�ndolo.
	   * @param archivo File con la ruta del archivo a descifrar.
	   */
	

	public static void descifrado(File archivo) {

		try {

			// Apertura del fichero que se va a descifrar
			InputStream input = new FileInputStream(archivo.getAbsolutePath());

			// Carga del Header del archivo por par�metros
			if (!head.load(input)) {
				System.out.println("Error en la carga de la cabecera.");
			}

			// Pedimos la contrase�a al usuario.
			System.out.print("Introducir contrase�a para el DEScifrado:  ");
			String pass = br.readLine();
			char[] passw = pass.toCharArray();
			PBEKeySpec password = new PBEKeySpec(passw);

			// SecrectKeyFactory: Nos permitir� generar la clave de sesi�n para el algoritmo
			// elegido;
			// La crearemos indicando el algoritmo para el que se quiere la clave:
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(head.getAlgorithm());
			SecretKey secretKeyPass = keyFactory.generateSecret(password);

			PBEParameterSpec pPS = new PBEParameterSpec(head.getSalt(), 64);

			// Cipher: Clase cifrador; la crearemos indicando el algoritmo
			// y despu�s la iniciaremos con la clave y los par�metros:
			Cipher cifrado;
			cifrado = Cipher.getInstance(head.getAlgorithm());
			cifrado.init(Cipher.DECRYPT_MODE, secretKeyPass, pPS);

			// Creaci�n del archivo descifrado
			FileOutputStream archivoDescifrado = new FileOutputStream(archivo.getAbsolutePath() + ".des");

			// Creacion flujo descifrado
			CipherInputStream ciflujoIn = new CipherInputStream(input, cifrado);

			byte[] bloqueBytes = new byte[1024];
			int i;
			while ((i = ciflujoIn.read(bloqueBytes)) != -1) {

				archivoDescifrado.write(bloqueBytes, 0, i);
				System.out.print(bloqueBytes.length + " .");
			}

			// Cerrado de flujos.
			ciflujoIn.close();
			input.close();
			archivoDescifrado.close();

			DecimalFormat df = new DecimalFormat("#.00");
			float longitud = new File(archivo.getAbsolutePath() + ".des").length();
			
			String peso = "";

			if (longitud > 1024000000)
				peso = (df.format(longitud / 1024000000) + " Gb");
			else if (longitud > 1024000)
				peso = (df.format(longitud / 1024000) + " Mb");
			else if (longitud > 1024)
				peso = (df.format(longitud / 1024) + " Kb");
			else
				peso = (df.format(longitud) + " bytes");

			System.out.println();
			System.out
					.println(" _____________________________________________________________________________________");
			System.out.println(
					"|  ARCHIVO" + archivo.getName() +  " DESCIFRADO CORRECTAMENTE" + "(" + peso +")");
			System.out
					.println("|_____________________________________________________________________________________");
		} catch (NoSuchPaddingException | InvalidKeyException | IOException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | InvalidKeySpecException e) {

			System.out.println("La contrase�a introducida no es correcta.");
			System.out.println("");
		}

	}
	
	/**
	   * M�dulo que permite elegir el algoritmo con el que se cifrar� el archivo. Permite elegir entre cuatro tipos de algoritmos distintos y
	   * almacena este nuevo algoritmo en el objeto header que se ha creado.
	   * En caso de no poder ser modificado mostrar� un mensaje de error adivirti�ndolo. 
	   */

	public static void cambiarAlgoritmo() throws NumberFormatException, IOException {

		System.out.println();
		System.out.println("Seleccione el algoritmo que desea usar: ");
		System.out.println(" 1.PBEWithMD5AndDES");
		System.out.println(" 2.PBEWithMD5AndTripleDES");
		System.out.println(" 3.PBEWithSHA1AndDESede");
		System.out.println(" 4.PBEWithSHA1AndRC2_40");

		int opcion = Integer.parseInt(br.readLine());

		if (opcion >= 1 && opcion <= 4) {
			if (opcion == 1) {
				head.setAlgorithm("PBEWithMD5AndDES");
				System.out.println("Algoritmo cambiado a PBEWithMD5AndDES");
			}

			if (opcion == 2) {
				head.setAlgorithm("PBEWithMD5AndTripleDES");
				System.out.println("Algoritmo cambiado a PBEWithMD5AndTripleDES");
			}

			if (opcion == 3) {
				head.setAlgorithm("PBEWithSHA1AndDESede");
				System.out.println("Algoritmo cambiado a PBEWithSHA1AndDESede");
			}

			if (opcion == 4) {
				head.setAlgorithm("PBEWithSHA1AndRC2_40");
				System.out.println("Algoritmo cambiado a PBEWithSHA1AndRC2_40");
			}
		} else {
			System.out.println("Valor incorrecto.");
		}

	}

	public static void main(String[] args)
			throws IOException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		boolean salir = false;
		System.out.println(" ______________________________________________________________________________________ ");
		System.out.println("|                Pr�ctica 2 - Cifrado Sim�trico con la JCA de JAVA                     |");
		System.out.println("|______________________________________________________________________________________|");
		System.out.println("      Autores:    Juan Antonio Silva Luj�n   y    Alberto Mangut Bustamante             ");

		while (salir != true) {
			System.out.println("====================================================================================");
			System.out.println();
			System.out.println();
			System.out.println("Seleccione la opci�n deseada: ");
			System.out.println(" 1.  Cambiar algoritmo, (por defecto) = " + head.getAlgorithm());
			System.out.println(" 2.  Cifrar archivo");
			System.out.println(" 3.  Descifrar archivo");
			System.out.println(" 4.  Salir            ");
			System.out.print("->  ");
			File archivo = new File(args[0]);

			int opcion = Integer.parseInt(br.readLine());

			// Archivo inicial de ejemplo

			if (opcion == 1) {
				cambiarAlgoritmo();
			}

			if (opcion == 2) {
				System.out.println();
				System.out.println("CIFRANDO archivo ......");

				cifrado(archivo);

			}

			if (opcion == 3) {
				System.out.println();
				System.out.println("DESCIFRANDO archivo ......");

				descifrado(archivo);

			}
			if (opcion == 4) {
				System.out.println("Saliendo del programa............................");
				salir = true;
				break;
			}

			if (opcion != 1 && opcion != 2 && opcion != 3)
				System.out.println("ERROR. Introduzca [1, 2 o 3]");

		}
	}

}
