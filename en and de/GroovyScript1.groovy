import groovy.sql.Sql
import groovy.json.JsonSlurper
import org.apache.commons.lang3.RandomStringUtils
import com.sv.ElektraEncryption

def requestBody = mockRequest.getRequestContent()
log.info "Request body: " + requestBody

def object = new JsonSlurper().parseText(requestBody)

def idOrdenPago = object.deposito.numeroCuenta
def idTipoOperacion = object.idTipoOperacion
def country = object.deposito.origen.codigoPais

log.info "idTipoOperacion: " + idTipoOperacion
log.info "country: " + country
String id = RandomStringUtils.randomAlphanumeric(30)

log.info "Trans ID: " + id
String encId = ElektraEncryption.encrypt(id)

log.info "Encrypted Trans ID: " + encId

context.mockService.setPropertyValue("transid", encId)
String decOrderPagoId = ElektraEncryption.decrypt(idOrdenPago)

log.info "numeroCuenta Decrypted: " + decOrderPagoId
if (decOrderPagoId.endsWith("101")) {
    return "ErrorResponse6.7"
}
else if (decOrderPagoId.endsWith("102")) {
    return "ErrorResponse6.8"
}
else if (decOrderPagoId.endsWith("111")) {
    return "ErrorResponse6.9"
}
else if (decOrderPagoId.endsWith("222") && idTipoOperacion == "2") {
    return "ErrorResponseCR1632"
}
else if (decOrderPagoId.endsWith("100")) {
    return "ErrorResponse"
}
else {
    try {
        def dbURL = ''
        def dbUserName = ''
        def dbPassword = ''
        def dbDriver = 'com.microsoft.sqlserver.jdbc.SQLServerDriver'

        def db = Sql.newInstance(dbURL, dbUserName, dbPassword, dbDriver)

        def sqlstr =
                "insert into VirtualService.dbo.ELEKTRA " +
                "(idOrdenPago,numeroCuenta) values('" +
                id + "', '" + decOrderPagoId + "')"

        log.info(sqlstr)

        db.execute(sqlstr)
        db.commit()
        db.close()

    } catch(Exception e) {
        log.info('DB Error')
        log.info(e.getMessage())
    }

    return "SuccessResponse"
}
