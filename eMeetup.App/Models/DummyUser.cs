using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eMeetup.App.Models;

public class DummyUser
{
    // User-provided fields (from registration)
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public Gender Gender { get; set; } = Gender.Other;
    public DateTime DateOfBirth { get; set; } = DateTime.Now.AddYears(-18);
    public string[] Roles { get; set; } = Array.Empty<string>();

    // Admin-editable fields
    public string Bio { get; set; } = string.Empty;
    public string ProfilePictureUrl { get; set; } = string.Empty;
    public string City { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public string Interests { get; set; } = string.Empty;
}
