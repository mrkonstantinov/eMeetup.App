using Microsoft.AspNetCore.Components.Forms;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;


namespace eMeetup.App.Models;

public class RegistrationRequest
{
    // Required fields from Keycloak config
    [Required(ErrorMessage = "Username is required")]
    [MinLength(3, ErrorMessage = "Username must be at least 3 characters")]
    [MaxLength(255, ErrorMessage = "Username cannot exceed 255 characters")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Please enter a valid email address")]
    [MaxLength(255, ErrorMessage = "Email cannot exceed 255 characters")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [MinLength(6, ErrorMessage = "Password must be at least 6 characters")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Please confirm your password")]
    [Compare("Password", ErrorMessage = "Passwords do not match")]
    public string ConfirmPassword { get; set; } = string.Empty;

    // Required user metadata from Keycloak config
    [Required(ErrorMessage = "Gender is required")]
    public Gender Gender { get; set; } = Gender.Other;

    [Required(ErrorMessage = "Date of birth is required")]
    public DateTime DateOfBirth { get; set; } = DateTime.Now.AddYears(-18);

    // 
    public string Bio { get; set; } = string.Empty;

    // Add properties for file upload
    [JsonIgnore]
    public IBrowserFile? ProfilePictureFile { get; set; }

    [JsonIgnore]
    public byte[]? ProfilePictureData { get; set; }

    public string City { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string Interests { get; set; } = string.Empty;

    // UI state property
    [JsonIgnore]
    public bool isRegistering { get; set; } = false;
}