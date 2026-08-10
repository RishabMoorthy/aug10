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

try {
    def dbURL = ''
    def dbUserName = ''
    def dbPassword = ''
    def dbDriver = 'com.microsoft.sqlserver.jdbc.SQLServerDriver'

    def db = Sql.newInstance(dbURL, dbUserName, dbPassword, dbDriver)

    def dbrow = db.firstRow("SELECT * FROM VirtualService.dbo.ELEKTRA WHERE idOrdenPago='" + transId + "'")

    db.commit()
    db.close()

    def country = dbrow.numeroCuenta
    log.info "country: " + country
    if (country == "NLD") {
        return "ErrorResponse"
    } else if (country == "ISR") {
        return "ErrorResponse6.10"
    } else {
        return "SuccessResponse"
    }

} catch (Exception e) {
    log.info "DB Error"
    log.info e.getMessage()
}
