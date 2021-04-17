package dev.jlarsen.authserverdemo;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.jlarsen.authserverdemo.exceptions.CodeRequestError;
import dev.jlarsen.authserverdemo.exceptions.RedirectUriException;
import dev.jlarsen.authserverdemo.models.AuthClient;
import dev.jlarsen.authserverdemo.models.CodeRequest;
import dev.jlarsen.authserverdemo.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Map;

@Controller
public class ViewController {

    @Autowired
    AuthService authService;

    @Autowired
    ObjectMapper objectMapper;

    /**
     * Authorization endpoint used by OAuth 2.0 client to request an auth code
     * @param params authorization request parameters (response_type, client_id, scope, state, redirect_uri)
     * @param response used to redirect error back to client if needed
     * @param model to be populated with client information if authorization request is valid
     * @param principal User who the requesting client belongs
     * @return view requesting User to approve client request, or redirect to client with error
     */
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping(value = "/authorize")
    public String getAuth(@RequestParam Map<String, String> params, HttpServletResponse response,
                          Model model, Principal principal) {
        // map params to codeRequest object
        CodeRequest codeRequest = objectMapper.convertValue(params, CodeRequest.class);
        // send codeRequest for verification
        CodeRequestError error = authService.verifyClientCodeRequest(codeRequest);

        if (error.name().equals("INVALID_REQUEST")) {
            // invalid client_id or redirect_uri so throw error locally (do not redirect)
            throw new RedirectUriException();
        } else if (!error.name().equals("NONE")) {
            // client_id and redirect_uri are good, so redirect error back to client
            try {
                response.sendRedirect(codeRequest.getRedirectUri() +
                        authService.getEncodedErrorParams(error) +
                        "&state=" + codeRequest.getState());
            } catch (IOException e) {
                e.printStackTrace();
                // since we know there is a client error, but can't redirect back to client for some reason,
                // let's just throw error locally
                throw new RedirectUriException();
            }
        }
        // verification succeeded without error, so ask user to approve
        AuthClient client = authService.getClient(codeRequest.getClientId());
        model.addAttribute(client);
        model.addAttribute(codeRequest);
        model.addAttribute("principalName", principal.getName());
        return "approve";
    }

    /**
     * Endpoint used when User has approved client request and auth code will be issued
     * @param codeRequest code request that was approved
     * @param principal User that approved access
     * @return redirect to client with auth code
     */
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping(value = "/approve")
    public RedirectView approveAccess(@ModelAttribute("codeRequest") CodeRequest codeRequest,
                                      Principal principal) {
        return new RedirectView(codeRequest.getRedirectUri() +
                "?state=" + codeRequest.getState() + "&code=" +
                authService.getAuthCode(codeRequest, principal));
    }

    /**
     * Endpoint used when User has denied client request
     * @param codeRequest code request that was denied
     * @return redirect to client with error
     */
    @PreAuthorize("hasAuthority('ROLE_USER')")
    @PostMapping(value = "/deny")
    public RedirectView denyAccess(@ModelAttribute("codeRequest") CodeRequest codeRequest) {
        return new RedirectView(codeRequest.getRedirectUri() +
                authService.getEncodedErrorParams(CodeRequestError.ACCESS_DENIED) +
                "&state=" + codeRequest.getState());
    }
}
