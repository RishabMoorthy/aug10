import groovy.sql.Sql
import groovy.json.JsonSlurper
import com.sv.ElektraEncryption

def requestBody = mockRequest.getRequestContent()
log.info "Request body: " + requestBody

def object = new JsonSlurper().parseText(requestBody)
def idTransaccion = object.idTransaccion

log.info "Encrypted Trans ID: " + idTransaccion
String transId = ElektraEncryption.decrypt(idTransaccion)

log.info "Decrypted Trans ID: " + transId

context.mockService.setPropertyValue("transid", transId)

try {
    def dbURL = ''
    def dbUserName = ''
    def dbPassword = ''
    def dbDriver = 'com.microsoft.sqlserver.jdbc.SQLServerDriver'

    def db = Sql.newInstance(dbURL, dbUserName, dbPassword, dbDriver)

    def dbrow = db.firstRow("SELECT * FROM VirtualService.dbo.ELEKTRA WHERE idOrdenPago='" + transId + "'")

    db.commit()
    db.close()

    def orderNo = dbrow.numeroCuenta
    log.info "numeroCuenta: " + orderNo
    if (orderNo.endsWith("201")) {
        context.mockService.setPropertyValue("PartnerCode", "C30001")
        context.mockService.setPropertyValue("Message", "BGE0040 | Error en el deposito no controlado, necesario corrección de datos titular de la cuenta.")
        return "ErrorResponse"

    } else if (orderNo.endsWith("202")) {
        context.mockService.setPropertyValue("PartnerCode", "C30001")
        context.mockService.setPropertyValue("Message", "BGE0336 | Error en el deposito no controlado. Cliente no existe, favor de validar cuenta.")
        return "ErrorResponse"

    } else if (orderNo.endsWith("203")) {
        context.mockService.setPropertyValue("PartnerCode", "CR1048")
        context.mockService.setPropertyValue("Message", "el cliente ha alcanzado el limite anual para enviar o recibir con el pais seleccionado")
        return "ErrorResponse"

    } else if (orderNo.endsWith("204")) {
        return "500ErrorResponse"

    } else if (orderNo.endsWith("205")) {
        return "ErrorResponse6.9"

    } else if (orderNo.endsWith("206")) {
        context.mockService.setPropertyValue("PartnerCode", "C123999")
        context.mockService.setPropertyValue("Message", "BGE0336 | Error en el deposito no controlado. Cliente no existe, favor de validar cuenta.")
        return "ErrorResponse"

    } else if (orderNo.endsWith("207")) {
        sleep(1200000)
        return "DelayErrorResponse"

    } else if (orderNo.endsWith("208")) {
        return "ErrorResponse1000"

    } else if (orderNo.endsWith("209")) {
        return "ErrorResponseCR1632"

    } else {
        return "SuccessResponse"
    }

} catch (Exception e) {
    log.info("DB Error")
    log.info(e.getMessage())
}
