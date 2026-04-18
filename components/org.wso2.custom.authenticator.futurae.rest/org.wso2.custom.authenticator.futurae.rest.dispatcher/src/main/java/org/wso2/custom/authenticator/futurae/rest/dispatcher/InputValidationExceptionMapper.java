package org.wso2.custom.authenticator.futurae.rest.dispatcher;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.custom.authenticator.futurae.rest.common.error.ErrorDTO;
import org.wso2.custom.authenticator.futurae.rest.common.error.ErrorResponse;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import java.util.Set;

import static org.wso2.custom.authenticator.futurae.rest.dispatcher.ErrorConstants.*;

/**
 * An exception mapper class that maps input validation exceptions.
 */
public class InputValidationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    private static final Log LOG = LogFactory.getLog(InputValidationExceptionMapper.class);

    @Override
    public Response toResponse(ConstraintViolationException e) {

        StringBuilder description = new StringBuilder();
        Set<ConstraintViolation<?>> constraintViolations = e.getConstraintViolations();

        for (ConstraintViolation constraintViolation : constraintViolations) {
            if (StringUtils.isNotBlank(description)) {
                description.append(" ");
            }
            description.append(constraintViolation.getMessage());
        }

        if (StringUtils.isBlank(description)) {
            description = new StringBuilder(ERROR_DESCRIPTION);
        }

        ErrorDTO errorDTO = new ErrorResponse.Builder()
                .withCode(ERROR_CODE)
                .withMessage(ERROR_MESSAGE)
                .withDescription(description.toString())
                .build(LOG, e.getMessage(), true);

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
