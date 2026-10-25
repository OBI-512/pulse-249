"""Deterministic, meaningful baseline dataset for a fresh FTTW installation."""

from __future__ import annotations
import asyncio
import uuid
from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.models import (
    AuditLog, City, Customer, CustomerService, Device, DeviceCandidate, DeviceGroup,
    DeviceGroupMembership, DeviceIP, DeviceInterface,
    DiscoveryJob, DiscoveryResult, DeviceType, Location, Network, Permission, Role,
    RolePermission, User, UserPermission, UserResourceScope, UserRole, Sector, SystemSetting,
    TelemetryProfile,
)
from app.security.passwords import hash_password
from app.security.permission_dependencies import expand_permission_codes
from app.security.runtime_safety import ensure_demo_seed_allowed
from app.services.device_domain import create_domain_placement
from app.services.hierarchy import resolve_effective_hierarchy
from app.availability.service import ensure_device_availability

NAMESPACE = uuid.UUID("8d3a2d89-4e70-4e36-9b1a-4d0f6e1c1f55")
DEMO_SEED_MARKER_KEY = "internal.demo_seed.version"
DEMO_SEED_VERSION = 1
CONTROLLED = [
    ("Access Point","ACCESS_POINT"), ("CPE","CPE"), ("Sector","SECTOR"), ("Switch","SWITCH"),
    ("Router","ROUTER"), ("Firewall","FIREWALL"), ("Server","SERVER"),
    ("Wireless Bridge","WIRELESS_BRIDGE"), ("Network Device","NETWORK_DEVICE"), ("Other","OTHER"),
]
BASELINE_TELEMETRY_METRICS = (
    {"key": "sys_uptime_seconds", "oid": "1.3.6.1.2.1.1.3.0", "kind": "COUNTER", "unit": "seconds", "transform": "timeticks_seconds"},
    {"key": "sys_name", "oid": "1.3.6.1.2.1.1.5.0", "kind": "STATE", "transform": "raw"},
    {"key": "if_count", "oid": "1.3.6.1.2.1.2.1.0", "kind": "GAUGE", "unit": "interfaces", "transform": "int"},
)
BASELINE_TELEMETRY_DESCRIPTION = (
    "Safe opt-in Phase D SNMP telemetry profile. Availability remains independent."
)
PERMISSIONS = [
    ("user.read","User Read"), ("user.create","User Create"),
    ("user.update","User Update"), ("user.deactivate","User Deactivate"),
    ("user.password.reset","User Password Reset"),
    ("user.roles.manage","User Roles Manage"), ("user.permissions.manage","User Permissions Manage"),
    ("user.scopes.read","User Scopes Read"), ("user.scopes.manage","User Scopes Manage"),
    ("user.sessions.read","User Sessions Read"), ("user.sessions.manage","User Sessions Manage"),
    # Retained only as a legacy catalog entry.  New user-management endpoints
    # require the explicit permissions above.
    ("user.manage","User Management (Legacy)"),
    ("settings.read","Settings Read"), ("settings.manage","Settings Management"),
    ("settings.secret.read","Settings Secret Read"),
    ("device.read","Device Read"), ("device.create","Device Create"), ("device.update","Device Update"), ("device.delete","Device Delete"),
    ("device.remote_access.ssh","Device Remote Access - SSH"), ("device.remote_access.web","Device Remote Access - Web GUI"),
    ("device.configuration.read","Device Configuration Read"),
    ("device.configuration.capture","Device Configuration Capture"),
    ("device.configuration.apply","Device Configuration Apply"),
    ("device.configuration.restore","Device Configuration Restore"),
    ("device.configuration.template.read","Device Configuration Template Read"),
    ("device.configuration.template.manage","Device Configuration Template Manage"),
    ("group.read","Group Read"), ("group.create","Group Create"), ("group.update","Group Update"), ("group.delete","Group Delete"), ("group.membership.manage","Group Membership Manage"),
    ("placement.read","Placement Read"), ("placement.create","Placement Create"), ("placement.update","Placement Update"),
    ("relationship.read","Relationship Read"), ("relationship.create","Relationship Create"), ("relationship.delete","Relationship Delete"),
    ("discovery.read","Discovery Read"), ("discovery.run","Discovery Run"), ("discovery.flush","Discovery Flush"),
    ("candidate.read","Candidate Read"), ("candidate.review","Candidate Review"), ("candidate.register","Candidate Register"),
    ("audit.read","Audit Read"), ("audit.export","Audit Export"), ("topology.read","Topology Read"),
    ("alarm.read","Alarm Read"), ("alarm.acknowledge","Alarm Acknowledge"),
    ("alarm.assign","Alarm Assign"), ("alarm.clear","Alarm Clear"),
    ("maintenance.read","Maintenance Read"), ("maintenance.manage","Maintenance Manage"),
    ("notification.read","Notification Read"), ("notification.manage","Notification Manage"),
    ("network.read","Network Read"), ("network.create","Network Create"), ("network.update","Network Update"),
    ("network.delete","Network Delete"),
    ("geo.read","Geography Read"), ("geo.create","Geography Create"), ("geo.update","Geography Update"), ("geo.delete","Geography Delete"),
    ("customer.read","Customer Read"), ("customer.create","Customer Create"), ("customer.update","Customer Update"), ("customer.delete","Customer Delete"),
    ("onboarding.read","Onboarding Read"), ("onboarding.create","Onboarding Create"), ("onboarding.register","Onboarding Register"),
    ("physical_movement.sector","Physical Sector Movement"),
    ("physical_movement.cpe","Physical CPE Movement"),
    ("physical_movement.access_point","Physical Access Point Movement"),
    ("recycle_bin.read","Recycle Bin Read"),
    ("recycle_bin.restore","Recycle Bin Restore"),
    ("recycle_bin.purge","Recycle Bin Purge"),
    ("restore_points.read","Restore Points Read"),
    ("restore_points.create","Restore Points Create"),
    ("restore_points.restore","Restore Points Restore"),
    ("restore_points.delete","Restore Points Delete"),
    ("logs.read","Operational Logs Read"),
    ("logs.export","Operational Logs Export"),
    ("telemetry.read","Telemetry Read"), ("telemetry.manage","Telemetry Manage"),
    ("data_lifecycle.read","Data Lifecycle Read"), ("data_lifecycle.manage","Data Lifecycle Manage"),
    ("data_exchange.read","Data Exchange Read"), ("data_exchange.import","Data Exchange Import"), ("data_exchange.export","Data Exchange Export"),
    ("report.read","Report Read"), ("report.manage","Report Manage"), ("report.export","Report Export"),
    ("report.schedule","Report Schedule"), ("report.sensitive","Report Sensitive Fields"),
]
ADMIN = {x[0] for x in PERMISSIONS}
OPERATOR = ADMIN - {
    "user.read", "user.create", "user.update", "user.deactivate",
    "user.password.reset", "user.roles.manage", "user.permissions.manage", "user.scopes.read", "user.scopes.manage", "user.sessions.read", "user.sessions.manage",
    "user.manage", "settings.read", "settings.manage", "settings.secret.read",
    "device.delete", "device.remote_access.ssh", "device.remote_access.web",
    "device.configuration.read", "device.configuration.capture", "device.configuration.apply", "device.configuration.restore",
    "device.configuration.template.read", "device.configuration.template.manage",
    "group.delete", "relationship.delete", "discovery.flush",
    "physical_movement.sector", "physical_movement.cpe",
    "physical_movement.access_point",
    "recycle_bin.read", "recycle_bin.restore", "recycle_bin.purge",
    "restore_points.read", "restore_points.create", "restore_points.restore", "restore_points.delete",
    "logs.read", "logs.export",
    "audit.read", "audit.export",
    "network.delete", "geo.delete", "customer.delete", "notification.manage",
    "telemetry.manage", "data_lifecycle.manage", "data_exchange.import", "report.sensitive",
}
VIEWER = {
    "device.read", "group.read", "placement.read", "relationship.read",
    "discovery.read", "candidate.read", "topology.read", "network.read",
    "geo.read", "customer.read", "onboarding.read", "alarm.read", "maintenance.read", "notification.read",
    "telemetry.read", "report.read",
}
ADMIN_VIEWER = {
    "user.read", "settings.read",
    "device.read", "group.read", "placement.read", "relationship.read",
    "discovery.read", "candidate.read", "topology.read", "network.read",
    "geo.read", "customer.read", "onboarding.read", "alarm.read", "maintenance.read", "notification.read",
    "telemetry.read", "data_lifecycle.read", "data_exchange.read", "report.read",
}

def did(key: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, key)

async def one(db, model, *conditions):
    return await db.scalar(select(model).where(*conditions))

async def ensure(db, model, obj, *conditions):
    found = await one(db, model, *conditions)
    if found is not None:
        return found
    db.add(obj)
    await db.flush()
    return obj

async def ensure_baseline_telemetry_catalog(db):
    """Ensure controlled device types and their non-destructive telemetry defaults.

    Profiles are keyed by device type, so an existing profile is returned
    unchanged.  This deliberately repairs missing post-migration seed data
    without resetting operator-customized telemetry configuration.
    """
    types = {}
    for name, code in CONTROLLED:
        types[code] = await ensure(
            db,
            DeviceType,
            DeviceType(
                id=did(f"type:{code}"),
                name=name,
                code=code,
                description=f"FTTW controlled type: {name}",
                is_active=True,
            ),
            DeviceType.code == code,
        )

    profiles = {}
    for _, code in CONTROLLED:
        profiles[code] = await ensure(
            db,
            TelemetryProfile,
            TelemetryProfile(
                id=did(f"telemetry_profile:{code}"),
                device_type_id=types[code].id,
                name=f"{code} Standard",
                enabled=False,
                protocol="SNMP",
                interval_seconds=900,
                timeout_seconds=5,
                retries=1,
                max_metrics=32,
                metric_definitions=[dict(metric) for metric in BASELINE_TELEMETRY_METRICS],
                vendor_extensions={},
                description=BASELINE_TELEMETRY_DESCRIPTION,
            ),
            TelemetryProfile.device_type_id == types[code].id,
        )
    return types, profiles

async def seed():
    ensure_demo_seed_allowed()
    async with AsyncSessionLocal() as db:
        marker = await one(
            db,
            SystemSetting,
            SystemSetting.key == DEMO_SEED_MARKER_KEY,
        )

        # Migration 0026 runs before the deterministic device-type catalog is
        # populated on a fresh installation.  Reconcile the required types and
        # missing per-type telemetry profiles on every allowed seed invocation,
        # including restarts after the one-time demo marker already exists.
        types, _ = await ensure_baseline_telemetry_catalog(db)
        if marker is not None:
            await db.commit()
            print(
                "Baseline telemetry catalog reconciled; deterministic demo seed "
                f"already completed and marker {DEMO_SEED_MARKER_KEY} is present."
            )
            return

        # RBAC
        roles = {}
        for code, name, description in [
            ("administrator", "Administrator", "Full administrative access."),
            ("operator", "Operator", "Operational access without destructive administration."),
            ("administrative_viewer", "Administrative Viewer", "Read-only operational access plus administrative visibility."),
            ("viewer", "Viewer", "Read-only operational access."),
            ("restricted", "Restricted", "Minimal role with no operational permissions; add only the required direct permissions."),
        ]:
            roles[code] = await ensure(db, Role, Role(id=did(f"role:{code}"), code=code, name=name, description=description), Role.code == code)
        perms = {}
        for code, name in PERMISSIONS:
            perms[code] = await ensure(db, Permission, Permission(id=did(f"perm:{code}"), code=code, name=name, description=f"{name} permission"), Permission.code == code)
        role_map = {
            "administrator": set(expand_permission_codes(ADMIN)),
            "operator": set(expand_permission_codes(OPERATOR)),
            "administrative_viewer": set(expand_permission_codes(ADMIN_VIEWER)),
            "viewer": set(expand_permission_codes(VIEWER)),
            "restricted": set(),
        }
        for role_code, codes in role_map.items():
            for code in codes:
                if await one(db, RolePermission, RolePermission.role_id==roles[role_code].id, RolePermission.permission_id==perms[code].id) is None:
                    db.add(RolePermission(id=did(f"roleperm:{role_code}:{code}"), role_id=roles[role_code].id, permission_id=perms[code].id))
        # Users
        for username, role_code, password in [
            ("admin","administrator","Admin123!"),
            ("operator","operator","Operator123!"),
            ("adminview","administrative_viewer","AdminView123!"),
            ("viewer","viewer","Viewer123!"),
        ]:
            user = await one(db, User, User.username==username)
            if user is None:
                user = User(id=did(f"user:{username}"), external_subject=f"local:{username}", username=username,
                            display_name=username.replace("adminview","Administrative Viewer").title(),
                            password_hash=hash_password(password), is_active=True, metadata_={"seed":"baseline"})
                db.add(user); await db.flush()
            if await one(db, UserRole, UserRole.user_id==user.id, UserRole.role_id==roles[role_code].id) is None:
                db.add(UserRole(id=did(f"userrole:{username}:{role_code}"), user_id=user.id, role_id=roles[role_code].id))
            if await one(db, UserResourceScope, UserResourceScope.user_id==user.id, UserResourceScope.scope_type=="GLOBAL") is None:
                db.add(UserResourceScope(
                    id=did(f"user-resource-scope:{username}:global"),
                    user_id=user.id,
                    scope_type="GLOBAL",
                    assigned_by_user_id=None,
                ))

        # Geography: 2 networks, 2 cities each, 2 locations each.
        networks=[]; locations=[]
        for ni in range(1,3):
            n=await ensure(db, Network, Network(id=did(f"net:{ni}"), name=f"Network {ni}", code=f"NET-{ni:02d}", status="ACTIVE"), Network.code==f"NET-{ni:02d}")
            networks.append(n)
            for ci in range(1,3):
                c=await ensure(db, City, City(id=did(f"city:{ni}:{ci}"), network_id=n.id, name=f"City {ni}-{ci}", code=f"N{ni}-C{ci}"), City.network_id==n.id, City.code==f"N{ni}-C{ci}")
                for li in range(1,3):
                    loc=await ensure(db, Location, Location(id=did(f"loc:{ni}:{ci}:{li}"), city_id=c.id, name=f"Location {ni}-{ci}-{li}", code=f"N{ni}-C{ci}-L{li}", address=f"{100+li} FTTW Avenue", latitude=30+ni, longitude=31+ci), Location.city_id==c.id, Location.code==f"N{ni}-C{ci}-L{li}")
                    locations.append(loc)

        # Four sectors: three customer-access sectors and one backhaul sector.
        sector_defs=[(0,"SECTOR-A","Customer Access A","CUSTOMER_ACCESS"),
                      (1,"SECTOR-B","Customer Access B","CUSTOMER_ACCESS"),
                      (2,"SECTOR-C","Customer Access C","CUSTOMER_ACCESS"),
                      (3,"SECTOR-BH","Backhaul Sector","BACKHAUL")]
        sectors=[]
        for idx, code, name, role in sector_defs:
            loc=locations[idx % 3]
            s=await ensure(db, Sector, Sector(id=did(f"sector:{code}"), location_id=loc.id, name=name, code=code, sequence_number=idx+1, role=role), Sector.location_id==loc.id, Sector.code==code)
            sectors.append(s)

        # Device helper
        async def device(code, type_code, location_id=None, sector_id=None, parent_id=None, role=None, ip_suffix=None):
            d=await one(db, Device, Device.display_name==code)
            if d is None:
                d=Device(id=did(f"device:{code}"), device_type_id=types[type_code].id, display_name=code,
                         hostname=code.lower(), vendor="FTTW", model=type_code, lifecycle_state="ACTIVE",
                         operational_state="UP", management_protocol="ICMP", metadata_={"seed":"baseline"})
                db.add(d); await db.flush()
            await ensure_device_availability(db, d)
            await create_domain_placement(
                db,
                d,
                type_code,
                location_id=location_id,
                sector_id=sector_id if type_code == "SECTOR" else None,
                parent_device_id=parent_id,
                sector_role=role,
            )
            ip=f"10.50.{1 if type_code in {'SECTOR','CPE','ACCESS_POINT'} else 2}.{ip_suffix}"
            if await one(db, DeviceIP, DeviceIP.device_id==d.id, DeviceIP.ip_address==ip) is None:
                db.add(DeviceIP(id=did(f"ip:{code}"), device_id=d.id, ip_address=ip, address_family=4, is_management=True, is_primary=True, source="SEED"))
            for ix in (0,1):
                if await one(db, DeviceInterface, DeviceInterface.device_id==d.id, DeviceInterface.interface_name==f"eth{ix}") is None:
                    db.add(DeviceInterface(id=did(f"iface:{code}:{ix}"), device_id=d.id, interface_name=f"eth{ix}", interface_index=ix+1, operational_status="UP", administrative_status="UP"))
            return d

        sector_devices=[]
        for i,s in enumerate(sectors):
            sector_devices.append(await device(s.code,"SECTOR",sector_id=s.id,ip_suffix=10+i))

        cpes=[]; aps=[]
        assignments=[0,0,0,1,1,1,2,2]  # multiple CPEs per sector
        for i,si in enumerate(assignments,1):
            c=await device(f"CPE-{i:02d}","CPE",parent_id=sector_devices[si].id,ip_suffix=30+i)
            a=await device(f"AP-{i:02d}","ACCESS_POINT",parent_id=c.id,ip_suffix=60+i)
            cpes.append(c); aps.append(a)

        for i in range(1,4):
            await device(f"SW-{i:02d}","SWITCH",location_id=locations[(i-1)%len(locations)].id,ip_suffix=10+i)
        await device("RTR-01","ROUTER",location_id=locations[0].id,ip_suffix=20)
        await device("FW-01","FIREWALL",location_id=locations[0].id,ip_suffix=21)
        await device("SRV-01","SERVER",location_id=locations[1].id,ip_suffix=22)

        # Customers and one service per CPE/AP.
        for i,(cpe,ap,si) in enumerate(zip(cpes,aps,assignments),1):
            cust=await ensure(db, Customer, Customer(id=did(f"customer:{i}"),customer_code=f"CUST-{i:03d}",name=f"Customer {i:02d}",status="ACTIVE"), Customer.customer_code==f"CUST-{i:03d}")
            code=f"SVC-{i:03d}"
            if await one(db,CustomerService,CustomerService.service_code==code) is None:
                db.add(CustomerService(id=did(f"service:{code}"),customer_id=cust.id,sector_id=sectors[si].id,service_code=code,status="ACTIVE",cpe_device_id=cpe.id,access_point_device_id=ap.id,metadata_={"seed":"baseline"}))

        # Groups independent of networks.
        # Built-in type groups (including All Access Points) are seeded by
        # migration 0015 and are query-backed; demo data must not recreate
        # manual lookalikes or stored memberships for them.
        group_defs=[
            ("CITY-CPE","City 1 CPEs","CITY",None,(await one(db,City,City.code=="N1-C1")).id,None,None,"CPE",None),
            ("BACKHAUL","Backhaul Sectors","GLOBAL",None,None,None,None,"SECTOR","BACKHAUL"),
            ("LOC-SW","Location 1 Switches","LOCATION",None,None,locations[0].id,None,"SWITCH",None),
        ]
        for code,name,scope,nid,cid,lid,sid,ds,role in group_defs:
            g=await one(db,DeviceGroup,DeviceGroup.code==code)
            if g is None:
                g=DeviceGroup(id=did(f"group:{code}"),name=name,code=code,scope_type=scope,network_id=nid,city_id=cid,location_id=lid,sector_id=sid,device_scope=ds,sector_role=role,metadata_={"seed":"baseline"})
                db.add(g); await db.flush()
        # Add valid memberships
        groups={g.code:g for g in (await db.scalars(select(DeviceGroup))).all()}
        for s in sectors:
            if s.role=="BACKHAUL" and await one(db,DeviceGroupMembership,DeviceGroupMembership.device_id==s.sector_device_id,DeviceGroupMembership.group_id==groups["BACKHAUL"].id) is None:
                db.add(DeviceGroupMembership(id=did(f"membership:bh:{s.id}"),device_id=s.sector_device_id,group_id=groups["BACKHAUL"].id))
        for c in cpes:
            hierarchy=await resolve_effective_hierarchy(db,c)
            city=await one(db,City,City.id==hierarchy.city_id)
            if city.code=="N1-C1" and await one(db,DeviceGroupMembership,DeviceGroupMembership.device_id==c.id,DeviceGroupMembership.group_id==groups["CITY-CPE"].id) is None:
                db.add(DeviceGroupMembership(id=did(f"membership:citycpe:{c.id}"),device_id=c.id,group_id=groups["CITY-CPE"].id))
        for d in (await db.scalars(select(Device))).all():
            hierarchy=await resolve_effective_hierarchy(db,d)
            if hierarchy.location_id==locations[0].id and (await one(db,DeviceType,DeviceType.id==d.device_type_id)).code=="SWITCH":
                if await one(db,DeviceGroupMembership,DeviceGroupMembership.device_id==d.id,DeviceGroupMembership.group_id==groups["LOC-SW"].id) is None:
                    db.add(DeviceGroupMembership(id=did(f"membership:sw:{d.id}"),device_id=d.id,group_id=groups["LOC-SW"].id))
        # This non-recoverable internal marker is written in the same commit as
        # the full dataset. A failed/partial seed therefore remains retryable,
        # while later process restarts can never recreate recycled deterministic
        # identities behind the administrator's back.
        db.add(
            SystemSetting(
                id=did(f"setting:{DEMO_SEED_MARKER_KEY}"),
                key=DEMO_SEED_MARKER_KEY,
                value={"version": DEMO_SEED_VERSION},
                description="Internal one-time deterministic demo seed marker.",
                is_secret=False,
            )
        )
        await db.commit()
        print("Fresh baseline demo data seeded successfully.")
        print("Networks: 2 | Cities: 4 | Locations: 8 | Sectors: 4 (3 customer-access, 1 backhaul)")
        print("CPEs: 8 | Access Points: 8 | Switches: 3 | Customers/Services: 8")
        print("Users: admin / operator / adminview / viewer")

if __name__ == "__main__":
    asyncio.run(seed())

