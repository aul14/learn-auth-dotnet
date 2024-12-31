using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.Data;
using API.Dtos;
using API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Authorize(Roles = "Admin, User")]
    [ApiController]
    [Route("api/[controller]")]
    public class RolesController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<AppUser> _userManager;
        private readonly AppDbContext _context;
        public RolesController(RoleManager<IdentityRole> roleManager, UserManager<AppUser> userManager, AppDbContext context)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _context = context;
        }

        [HttpPost]
        public async Task<IActionResult> CreateRole([FromBody] CreateRoleDto createRoleDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var roleExists = await _roleManager.RoleExistsAsync(createRoleDto.RoleName!);

            if (roleExists)
            {
                return BadRequest("Role already exists");
            }

            var roleResult = await _roleManager.CreateAsync(new IdentityRole(createRoleDto.RoleName!));

            if (roleResult.Succeeded)
            {
                return Ok(new { message = "Role created successfully." });
            }
            else
            {
                return BadRequest(roleResult.Errors);
            }
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<RoleResponseDto>>> GetRoles()
        {
            var rolesWithCounts = await (from role in _roleManager.Roles
                                         join userRole in _context.UserRoles on role.Id equals userRole.RoleId into usersInRole
                                         select new RoleResponseDto
                                         {
                                             Id = role.Id,
                                             Name = role.Name,
                                             TotalUsers = usersInRole.Count()
                                         }).ToListAsync();
            return Ok(new
            {
                success = true,
                data = rolesWithCounts
            });
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);

            if (role is null)
            {
                return NotFound("Role not found");
            }

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok(new
                {
                    success = true,
                    message = "Role deleted successfully"
                });
            }
            else
            {
                return BadRequest(new
                {
                    success = false,
                    message = "Role deleted failed"
                });
            }
        }

        [HttpPost("assign")]
        public async Task<IActionResult> AssignRole([FromBody] RoleAssignDto roleAssignDto)
        {
            var user = await _userManager.FindByIdAsync(roleAssignDto.UserId!);

            if (user is null)
            {
                return NotFound("User not found");
            }

            var role = await _roleManager.FindByIdAsync(roleAssignDto.RoleId!);

            if (role is null)
            {
                return NotFound("Role not found");
            }

            var result = await _userManager.AddToRoleAsync(user, role.Name!);

            if (result.Succeeded)
            {
                return Ok(new
                {
                    success = true,
                    message = "Role assigned successfully"
                });
            }
            else
            {
                return BadRequest(new
                {
                    success = false,
                    message = "Role assigned failed"
                });
            }
        }
    }
}