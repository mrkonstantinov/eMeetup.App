using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace eMeetup.App.Models;

public class AccessTokenInfo
{
    public required string Email { get; set; }
    public required LoginResponse LoginResponse { get; set; }
    public required DateTime AccessTokenExpiration { get; set; }
}
