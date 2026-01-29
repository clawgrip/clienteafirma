/* Copyright (C) 2011 [Gobierno de Espana]
 * This file is part of "Cliente @Firma".
 * "Cliente @Firma" is free software; you can redistribute it and/or modify it under the terms of:
 *   - the GNU General Public License as published by the Free Software Foundation;
 *     either version 2 of the License, or (at your option) any later version.
 *   - or The European Software License; either version 1.1 or (at your option) any later version.
 * You may contact the copyright holder at: soporte.afirma@seap.minhap.es
 */

/** M&oacute;dulo de generaci&oacute;n de firmas digitales PAdES.
 *  <p>Tabla de compatibilidad respecto a generaci&oacute;n en cliente de variantes de PAdES:</p>
 *  <table border="1">
 *   <caption>Tabla de compatibilidad respecto a variantes de PAdES</caption>
 *   <tr>
 *    <td>PAdES-BES</td>
 *    <td>PAdES-EPES</td>
 *    <td>PAdES-T</td>
 *    <td>PAdES-C</td>
 *    <td>PAdES-X</td>
 *    <td>PAdES-XL</td>
 *    <td>PAdES-A</td>
 *   </tr>
 *   <tr>
 *    <td style="background-color: green;">Si<sup>1</sup></td>
 *    <td style="background-color: green;">Si<sup>1</sup></td>
 *    <td style="background-color: green;">Si<sup>1</sup> <sup>2</sup></td>
 *    <td style="background-color: red;">No</td>
 *    <td style="background-color: red;">No</td>
 *    <td style="background-color: red;">No</td>
 *    <td style="background-color: red;">No</td>
 *   </tr>
 *  </table>
 *  <p>
 *   <sup>1</sup> No se soporta la firma ni de ficheros adjuntos a los documentos PDF ni de ficheros empotrados en los documentos PDF.<br>
 *   <sup>2</sup> La generaci&oacute;n de los sellos de tiempo para PAdES-T necesita conexi&oacute;n
 *   con una autoridad de sellado de tiempo (TSA).
 *  </p>
 *  <p>
 *   Por defecto se generan firmas PAdES-BASIC, para lo que se incrusta una firma CAdES en el PDF utilizando
 *   <i>ETSI.CAdES.detached</i> como valor del sub-filtro de la firma.
 *  </p>
 *  <p>Los datos de firma electr&oacute;nica empotrados dentro de la estructura PDF equivalen a una firma CAdES.</p>
 *  <p>
 *   En general, no se soportan documentos PDF cifrados con certificados, con algoritmo AES256 o con cualquier otro medio introducido en
 *   versiones de Adobe Acrobat posteriores a la 9.
 *  </p>
 *  <p>
 *   <sup>*</sup> No se utilizan versiones m&aacute;s actuales de iText por incompatibilidades de licencias. Las funcionalidades
 *   de firma trif&aacute;sica PAdES requieren una vers&oacute;n modificada de iText 2.1.7 espec&iacute;fica del proyecto Cliente.
 *  </p>
 */
package es.gob.afirma.signers.pades;