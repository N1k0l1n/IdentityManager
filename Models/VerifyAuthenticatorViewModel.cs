using System.ComponentModel.DataAnnotations;

namespace IdentityManager.Models
{
    public class VerifyAuthenticatorViewModel
    {
        [Required]
        public string Code { get; set; }

        public string ReturnUrl { get; set; }

        [Display(Name = "Remeber me?")]
        public bool RememberMe { get; set; }
    }
}
